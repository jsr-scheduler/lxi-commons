//! The HTTPS server and request pieces with JSR's limits (`crates/api-rest/src/lib.rs`,
//! 3b75827): TLS by rustls with ring, 10 s to send the headers, 64 KiB bodies, 64
//! requests at once, and headers that keep responses out of caches and referrers.
//! Optional client certificates (`serve_tls_clients`). What a token, a cookie or a
//! certificate means is the service's decision.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;
use tokio::sync::Semaphore;

/// Largest request body.
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Requests handled at once; beyond that, 429.
pub const MAX_CONCURRENT: usize = 64;
/// Time a client has to send a request's headers once connected (slowloris, JSR S-18).
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Time a request has, once its headers are read, until its response is ready (body
/// included): a slow body cannot hold a slot for ever.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// `app` with the body limit, the concurrency limit and the response headers.
pub fn limits(app: Router) -> Router {
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT));
    app.layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(move |request: Request, next: Next| {
            let permits = Arc::clone(&permits);
            async move {
                let Ok(_permit) = permits.try_acquire_owned() else {
                    return StatusCode::TOO_MANY_REQUESTS.into_response();
                };
                match tokio::time::timeout(REQUEST_TIMEOUT, next.run(request)).await {
                    Ok(response) => response,
                    Err(_) => StatusCode::REQUEST_TIMEOUT.into_response(),
                }
            }
        }))
        .layer(middleware::from_fn(headers))
}

/// `nosniff` and `no-referrer` always; `no-store` unless the handler chose its caching.
async fn headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

/// Serves `app` (with [`limits`]) over HTTPS until `handle` asks for a graceful shutdown.
/// Handlers can read the peer with `ConnectInfo<SocketAddr>`.
pub async fn serve_tls(
    listen: SocketAddr,
    cert_pem: &Path,
    key_pem: &Path,
    app: Router,
    handle: axum_server::Handle<SocketAddr>,
) -> std::io::Result<()> {
    let config = rustls_config(cert_pem, key_pem, None)?;
    tuned(axum_server::bind_rustls(listen, config).handle(handle))
        .serve(limits(app).into_make_service_with_connect_info::<SocketAddr>())
        .await
}

/// [`serve_tls`], and a client may present a certificate signed by `client_ca_pem`: its
/// handlers then find a [`PeerCertificate`] among the request's extensions. A client
/// without one still connects (people sign in otherwise); one signed by another CA does
/// not finish the handshake.
pub async fn serve_tls_clients(
    listen: SocketAddr,
    cert_pem: &Path,
    key_pem: &Path,
    client_ca_pem: &Path,
    app: Router,
    handle: axum_server::Handle<SocketAddr>,
) -> std::io::Result<()> {
    let config = rustls_config(cert_pem, key_pem, Some(client_ca_pem))?;
    let acceptor = PeerAcceptor(axum_server::tls_rustls::RustlsAcceptor::new(config));
    tuned(axum_server::bind(listen).acceptor(acceptor).handle(handle))
        .serve(limits(app).into_make_service_with_connect_info::<SocketAddr>())
        .await
}

fn rustls_config(
    cert_pem: &Path,
    key_pem: &Path,
    client_ca_pem: Option<&Path>,
) -> std::io::Result<axum_server::tls_rustls::RustlsConfig> {
    // Only one process-wide provider; a second install is harmless.
    let _ = rustls::crypto::ring::default_provider().install_default();
    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        Arc::new(tls_config(cert_pem, key_pem, client_ca_pem)?),
    ))
}

/// HTTP/1.1 only, in ALPN and in the server (hyper-util's own `http1_only` alone still
/// sniffs an HTTP/2 preface): HTTP/2 streams would not have the header timeout (JSR
/// offered h2). A client that never finishes its headers is dropped; the TLS handshake has
/// its own 10 s limit in axum-server. After `acceptor`, which resets the HTTP version.
fn tuned<A>(server: axum_server::Server<SocketAddr, A>) -> axum_server::Server<SocketAddr, A> {
    let mut server = server.http1_only();
    server
        .http_builder()
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    server
}

/// The client certificate a request came with: the SHA-256 of its DER, the first of the
/// chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCertificate {
    pub sha256: [u8; 32],
}

/// rustls, then the client certificate into every request of the connection.
#[derive(Clone)]
struct PeerAcceptor(axum_server::tls_rustls::RustlsAcceptor);

type Accepted<I, S> = std::io::Result<(tokio_rustls::server::TlsStream<I>, WithPeer<S>)>;

impl<I, S> axum_server::accept::Accept<I, S> for PeerAcceptor
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = tokio_rustls::server::TlsStream<I>;
    type Service = WithPeer<S>;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Accepted<I, S>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let handshake = self.0.accept(stream, service);
        Box::pin(async move {
            use sha2::Digest;
            let (stream, inner) = handshake.await?;
            let peer = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(<[_]>::first)
                .map(|cert| PeerCertificate {
                    sha256: sha2::Sha256::digest(cert.as_ref()).into(),
                });
            Ok((stream, WithPeer { inner, peer }))
        })
    }
}

/// A connection's service that adds its [`PeerCertificate`], if any, to each request.
#[derive(Clone)]
pub struct WithPeer<S> {
    inner: S,
    peer: Option<PeerCertificate>,
}

impl<S, B> tower_service::Service<axum::http::Request<B>> for WithPeer<S>
where
    S: tower_service::Service<axum::http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: axum::http::Request<B>) -> Self::Future {
        if let Some(peer) = self.peer {
            request.extensions_mut().insert(peer);
        }
        self.inner.call(request)
    }
}

/// The server's certificate chain and key from PEM files, ALPN `http/1.1` only, and the
/// optional client CA.
fn tls_config(
    cert_pem: &Path,
    key_pem: &Path,
    client_ca_pem: Option<&Path>,
) -> std::io::Result<rustls::ServerConfig> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let invalid = |e: rustls::pki_types::pem::Error| std::io::Error::other(e.to_string());
    let other = |e: rustls::Error| std::io::Error::other(e.to_string());
    let certs = CertificateDer::pem_file_iter(cert_pem)
        .map_err(invalid)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(invalid)?;
    let key = PrivateKeyDer::from_pem_file(key_pem).map_err(invalid)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(other)?;
    let builder = match client_ca_pem {
        None => builder.with_no_client_auth(),
        Some(ca) => {
            let mut roots = rustls::RootCertStore::empty();
            for cert in CertificateDer::pem_file_iter(ca).map_err(invalid)? {
                roots.add(cert.map_err(invalid)?).map_err(other)?;
            }
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                provider,
            )
            .allow_unauthenticated()
            .build()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
            builder.with_client_cert_verifier(verifier)
        }
    };
    let mut config = builder.with_single_cert(certs, key).map_err(other)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// The token of `Authorization: Bearer <token>`.
pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// The value of the cookie `name`, from every `Cookie` header.
pub fn cookie<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(n, _)| *n == name)
        .map(|(_, value)| value)
}

fn cookie_text(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-_.~".contains(&b))
}

/// A `Set-Cookie` for a session: `HttpOnly; Secure; SameSite=Strict; Path=/`, with
/// `Max-Age` when given (0 clears it). Use a `__Host-` name so only this host can set it.
/// A name or value with other characters is refused.
pub fn session_cookie(name: &str, value: &str, max_age: Option<u64>) -> Option<HeaderValue> {
    let bare = name.strip_prefix("__Host-").unwrap_or(name);
    if bare.is_empty() || !cookie_text(bare) || !cookie_text(value) {
        return None;
    }
    let age = max_age.map_or_else(String::new, |a| format!("; Max-Age={a}"));
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; HttpOnly; Secure; SameSite=Strict{age}"
    ))
    .ok()
}
