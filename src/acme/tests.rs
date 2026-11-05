use super::{
    http::Http,
    state::{Journal, State, read_private},
};
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::{future::Future, time::Duration};

pub(super) struct Server {
    pub url: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
pub(super) async fn http_server<F, Fut>(handler: F) -> Server
where
    F: Fn(Request<Bytes>) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Response<Full<Bytes>>> + Send + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let handler = handler.clone();
            connections.spawn(async move {
                let service =
                    hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
                        let handler = handler.clone();
                        async move {
                            let (parts, body) = request.into_parts();
                            let body = body.collect().await.unwrap().to_bytes();
                            Ok::<_, std::convert::Infallible>(
                                handler(Request::from_parts(parts, body)).await,
                            )
                        }
                    });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Server { url, task }
}
#[test]
fn journal_lock_permissions_atomic_recovery_and_symlinks() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let namespace = "a".repeat(64);
    let state = State::open(root.path(), &namespace).unwrap();
    assert!(State::open(root.path(), &namespace).is_err());
    let mut journal = Journal {
        version: 1,
        domain: "example.test".into(),
        ..Journal::default()
    };
    state.save(&journal).unwrap();
    journal.next_attempt = 12345;
    state.save(&journal).unwrap();
    let file = root.path().join(format!("journal-{namespace}.json"));
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(state);
    let state = State::open(root.path(), &namespace).unwrap();
    assert_eq!(state.load().unwrap().unwrap().next_attempt, 12345);
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(state.load().is_err());
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = root.path().join("secret-link");
    symlink(&file, &link).unwrap();
    assert!(read_private(&link, 1024 * 1024).is_err());
}
#[tokio::test]
async fn http_rejects_cleartext_limits_body_and_cancels_deadline() {
    let server = http_server(|request| async move {
        let data = match request.uri().path() {
            "/large" => vec![b'x'; 4 * 1024 * 1024 + 1],
            "/slow" => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                vec![]
            }
            _ => vec![],
        };
        Response::new(Full::new(Bytes::from(data)))
    })
    .await;
    let http = Http::new(None, Duration::from_millis(200)).unwrap();
    let request = || {
        Request::builder()
            .uri(format!("{}/", server.url))
            .body(Full::new(Bytes::new()))
            .unwrap()
    };
    assert!(http.request(request()).await.is_err());
    let http = http.with_loopback_http();
    assert!(http.request(request()).await.is_ok());
    for path in ["large", "slow"] {
        let request = Request::builder()
            .uri(format!("{}/{path}", server.url))
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(http.request(request).await.is_err());
    }
}
