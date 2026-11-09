//! The HTTPS server and request pieces, with JSR's limits (3b75827).
#![forbid(unsafe_code, unused_must_use)]
#![forbid(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::dbg_macro
)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use lxi_http::server::{bearer, cookie, limits, serve_tls, session_cookie};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A current-thread runtime (`#[tokio::test]` expands to an allow the workspace forbids).
fn run<F: std::future::Future<Output = TestResult>>(test: F) -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(test)
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures")).join(name)
}

fn app() -> Router {
    Router::new()
        .route("/hello", get(|| async { "hello" }))
        .route("/echo", post(|body: String| async move { body }))
}

async fn send(app: Router, request: Request<Body>) -> TestResult<axum::response::Response> {
    Ok(limits(app).oneshot(request).await?)
}

#[test]
fn a_body_over_64_kib_is_refused() -> TestResult {
    run(async {
        let at_limit = "x".repeat(64 * 1024);
        let request = Request::post("/echo").body(Body::from(at_limit))?;
        assert_eq!(send(app(), request).await?.status(), StatusCode::OK);
        let over = "x".repeat(64 * 1024 + 1);
        let request = Request::post("/echo").body(Body::from(over))?;
        assert_eq!(
            send(app(), request).await?.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        Ok(())
    })
}

#[test]
fn every_response_carries_the_security_headers() -> TestResult {
    run(async {
        for path in ["/hello", "/nowhere"] {
            let response = send(app(), Request::get(path).body(Body::empty())?).await?;
            let headers = response.headers();
            let value = |name: header::HeaderName| headers.get(name).and_then(|v| v.to_str().ok());
            assert_eq!(
                value(header::X_CONTENT_TYPE_OPTIONS),
                Some("nosniff"),
                "{path}"
            );
            assert_eq!(
                value(header::REFERRER_POLICY),
                Some("no-referrer"),
                "{path}"
            );
            assert_eq!(value(header::CACHE_CONTROL), Some("no-store"), "{path}");
        }
        // A handler that chose its own caching keeps it.
        let cached = Router::new().route(
            "/file",
            get(|| async { ([(header::CACHE_CONTROL, "no-cache")], "f") }),
        );
        let response = send(cached, Request::get("/file").body(Body::empty())?).await?;
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-cache"))
        );
        Ok(())
    })
}

#[test]
fn too_many_requests_at_once_are_answered_429() -> TestResult {
    run(async {
        let gate = Arc::new(tokio::sync::Notify::new());
        let held = {
            let gate = Arc::clone(&gate);
            Router::new().route(
                "/wait",
                get(move || {
                    let gate = Arc::clone(&gate);
                    async move {
                        gate.notified().await;
                        "done"
                    }
                }),
            )
        };
        let service = limits(held);
        let mut waiting = Vec::new();
        for _ in 0..64 {
            let service = service.clone();
            waiting.push(tokio::spawn(async move {
                service
                    .oneshot(Request::get("/wait").body(Body::empty())?)
                    .await
                    .map(|r| r.status())
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
            }));
        }
        // Let all 64 reach the handler.
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        let late = tokio::time::timeout(
            Duration::from_secs(2),
            service
                .clone()
                .oneshot(Request::get("/wait").body(Body::empty())?),
        )
        .await
        .map_err(|_| "the 65th request waited instead of 429")??;
        assert_eq!(late.status(), StatusCode::TOO_MANY_REQUESTS);
        gate.notify_waiters();
        for task in waiting {
            let status = task.await?.map_err(|e| e.to_string())?;
            assert_eq!(status, StatusCode::OK);
        }
        Ok(())
    })
}

#[test]
fn bearer_and_cookie_are_read_and_nothing_else_is_trusted() -> TestResult {
    let mut h = HeaderMap::new();
    assert_eq!(bearer(&h), None);
    for (value, expected) in [
        ("Bearer abc", Some("abc")),
        ("Bearer  abc ", Some("abc")),
        ("Bearer ", None),
        ("bearer abc", None),
        ("Basic abc", None),
        ("abc", None),
    ] {
        h.insert(header::AUTHORIZATION, HeaderValue::from_str(value)?);
        assert_eq!(bearer(&h), expected, "{value}");
    }
    let mut h = HeaderMap::new();
    h.append(
        header::COOKIE,
        HeaderValue::from_static("a=1; __Host-s=tok"),
    );
    h.append(header::COOKIE, HeaderValue::from_static("b=2"));
    assert_eq!(cookie(&h, "__Host-s"), Some("tok"));
    assert_eq!(cookie(&h, "b"), Some("2"));
    assert_eq!(cookie(&h, "s"), None, "only the exact name");
    assert_eq!(cookie(&h, "c"), None);
    Ok(())
}

#[test]
fn the_session_cookie_is_http_only_secure_and_strict() -> TestResult {
    let set = session_cookie("__Host-s", "tok", None).ok_or("cookie")?;
    let text = set.to_str()?;
    assert!(text.starts_with("__Host-s=tok;"), "{text}");
    for attr in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
        assert!(text.contains(attr), "{text}");
    }
    assert!(!text.contains("Max-Age"));
    let clear = session_cookie("__Host-s", "", Some(0)).ok_or("cookie")?;
    assert!(clear.to_str()?.ends_with("; Max-Age=0"));
    // A value that would add attributes is refused.
    assert!(session_cookie("__Host-s", "tok; Domain=evil", None).is_none());
    assert!(session_cookie("__Host-s", "tok\r\nX: y", None).is_none());
    Ok(())
}

fn client() -> TestResult<tokio_rustls::TlsConnector> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::CertificateDer;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from_pem_file(fixture("ca.pem"))?)?;
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let mut config = config;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

async fn start() -> TestResult<(SocketAddr, axum_server::Handle<SocketAddr>)> {
    let handle = axum_server::Handle::new();
    let server = {
        let handle = handle.clone();
        let listen: SocketAddr = "127.0.0.1:0".parse()?;
        async move {
            serve_tls(
                listen,
                &fixture("tls-cert.pem"),
                &fixture("tls-key.pem"),
                app(),
                handle,
            )
            .await
        }
    };
    tokio::spawn(server);
    let address = handle.listening().await.ok_or("not listening")?;
    Ok((address, handle))
}

async fn connect(
    address: SocketAddr,
) -> TestResult<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let tcp = tokio::net::TcpStream::connect(address).await?;
    let name = rustls::pki_types::ServerName::try_from("localhost")?;
    Ok(client()?.connect(name, tcp).await?)
}

#[test]
fn https_end_to_end_with_the_limits() -> TestResult {
    run(async {
        let (address, handle) = start().await?;
        let mut tls = connect(address).await?;
        tls.write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut reply = Vec::new();
        tls.read_to_end(&mut reply).await?;
        let reply = String::from_utf8(reply)?;
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        assert!(reply.contains("x-content-type-options: nosniff"), "{reply}");
        assert!(reply.ends_with("hello"), "{reply}");
        handle.shutdown();
        Ok(())
    })
}

#[test]
fn a_client_that_never_finishes_its_headers_is_dropped() -> TestResult {
    run(async {
        let (address, handle) = start().await?;
        let mut tls = connect(address).await?;
        tls.write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\n")
            .await?;
        let started = Instant::now();
        let mut reply = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(20), tls.read_to_end(&mut reply))
            .await
            .map_err(|_| "still open after 20 s")?;
        let took = started.elapsed();
        // Closed (with or without a 408), never answered with the page.
        let _ = read;
        assert!(!String::from_utf8_lossy(&reply).contains("hello"));
        assert!(took >= Duration::from_secs(9), "{took:?}");
        assert!(took < Duration::from_secs(15), "{took:?}");
        handle.shutdown();
        Ok(())
    })
}

/// A client that sends its body slowly cannot hold one of the 64 slots for ever: the
/// response must be ready within REQUEST_TIMEOUT (automated review; JSR had no bound).
#[test]
fn a_request_that_never_finishes_its_body_times_out() -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()?
        .block_on(async {
            let never =
                futures_util::stream::pending::<Result<axum::body::Bytes, std::io::Error>>();
            let request = Request::post("/echo").body(Body::from_stream(never))?;
            let response = tokio::time::timeout(
                lxi_http::server::REQUEST_TIMEOUT.saturating_add(Duration::from_secs(1)),
                send(app(), request),
            )
            .await
            .map_err(|_| "no answer within REQUEST_TIMEOUT")??;
            assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
            Ok(())
        })
}

/// HTTP/2 is not offered: its streams would not have the header timeout (automated
/// review; JSR offered h2 through axum-server's default ALPN).
#[test]
fn only_http_1_1_is_negotiated() -> TestResult {
    run(async {
        let (address, handle) = start().await?;
        let tls = connect(address).await?;
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
        handle.shutdown();
        Ok(())
    })
}

/// An HTTP/2 preface without ALPN (prior knowledge) is not served as HTTP/2 either.
#[test]
fn an_http_2_preface_is_not_served() -> TestResult {
    run(async {
        let (address, handle) = start().await?;
        let tcp = tokio::net::TcpStream::connect(address).await?;
        let name = rustls::pki_types::ServerName::try_from("localhost")?;
        let mut tls = without_alpn()?.connect(name, tcp).await?;
        tls.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await?;
        let mut reply = vec![0_u8; 64];
        let read = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut reply)).await;
        let n = match read {
            Ok(Ok(n)) => n,
            Ok(Err(_)) | Err(_) => 0,
        };
        let reply = reply.get(..n).unwrap_or_default();
        // An HTTP/2 server answers with a SETTINGS frame (type 4 at byte 3).
        assert!(
            !(reply.len() >= 9 && reply.get(3) == Some(&4)),
            "served as HTTP/2: {reply:?}"
        );
        handle.shutdown();
        Ok(())
    })
}

fn without_alpn() -> TestResult<tokio_rustls::TlsConnector> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::CertificateDer;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from_pem_file(fixture("ca.pem"))?)?;
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}
