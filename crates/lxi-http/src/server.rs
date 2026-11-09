//! The HTTPS server and request pieces with JSR's limits (`crates/api-rest/src/lib.rs`,
//! 3b75827): TLS by rustls with ring, 10 s to send the headers, 64 KiB bodies, 64
//! requests at once, and headers that keep responses out of caches and referrers.
//! What a token or a cookie means is the service's decision.

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
    // Only one process-wide provider; a second install is harmless.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config(
        cert_pem, key_pem,
    )?));
    // HTTP/1.1 only, in ALPN and in the server (hyper-util's own `http1_only` alone still
    // sniffs an HTTP/2 preface): HTTP/2 streams would not have the header timeout (JSR
    // offered h2). A client that never finishes its headers is dropped; the TLS handshake
    // has its own 10 s limit in axum-server.
    let mut server = axum_server::bind_rustls(listen, config)
        .handle(handle)
        .http1_only();
    server
        .http_builder()
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    server
        .serve(limits(app).into_make_service_with_connect_info::<SocketAddr>())
        .await
}

/// The server's certificate chain and key from PEM files, ALPN `http/1.1` only.
fn tls_config(cert_pem: &Path, key_pem: &Path) -> std::io::Result<rustls::ServerConfig> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let invalid = |e: rustls::pki_types::pem::Error| std::io::Error::other(e.to_string());
    let certs = CertificateDer::pem_file_iter(cert_pem)
        .map_err(invalid)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(invalid)?;
    let key = PrivateKeyDer::from_pem_file(key_pem).map_err(invalid)?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| std::io::Error::other(e.to_string()))?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| std::io::Error::other(e.to_string()))?;
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
