//! Plain HTTP is a bounded website redirect listener, never a proxy ingress.
use super::Result;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, body::Incoming, service::service_fn};
use moon_naive_core::{config::Config, policy::Budget};
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::watch};
pub(super) async fn serve(
    listener: TcpListener,
    config: Arc<Config>,
    budget: Budget,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _=stop.changed()=>break,
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
            accepted=listener.accept()=>{
                let (socket,_) = accepted?;
                let Some(permit)=budget.acquire() else {continue};
                super::congestion::apply(&socket,config.transport.tcp_congestion)?;
                let config=config.clone();
                tasks.spawn(async move {
                    let _permit=permit;
                    let service=service_fn(move |req| {
                        let reply=response(req,&config);
                        async {Ok::<_,std::convert::Infallible>(reply)}
                    });
                    let _=tokio::time::timeout(Duration::from_secs(30),hyper::server::conn::http1::Builder::new().keep_alive(false).max_buf_size(32768).serve_connection(hyper_util::rt::TokioIo::new(socket),service)).await;
                });
            }
        }
    }
    tasks.abort_all();
    Ok(())
}
fn response(req: Request<Incoming>, config: &Config) -> Response<Full<Bytes>> {
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<http::uri::Authority>().ok());
    let site_name = host.as_ref().and_then(|host| config.site_name(host.host()));
    let status = if req.headers().get_all("host").iter().count() != 1 {
        400
    } else if site_name.is_none() {
        404
    } else if req.method() == http::Method::CONNECT {
        405
    } else if req.uri().scheme().is_some() || !req.uri().path().starts_with('/') {
        400
    } else {
        308
    };
    let mut builder = Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8");
    if status == 308 {
        let port = if config.listener.tcp.port() == 443 {
            String::new()
        } else {
            format!(":{}", config.listener.tcp.port())
        };
        builder = builder.header(
            "location",
            format!(
                "https://{}{port}{}",
                site_name.expect("validated redirect host"),
                req.uri()
                    .path_and_query()
                    .map(|p| p.as_str())
                    .unwrap_or("/")
            ),
        );
    }
    let text = format!(
        "{}\n",
        http::StatusCode::from_u16(status)
            .unwrap()
            .canonical_reason()
            .unwrap()
    );
    builder = builder.header("content-length", text.len());
    if status == 405 {
        builder = builder.header("allow", "GET, HEAD, POST, PUT, DELETE, OPTIONS, PATCH");
    }
    builder
        .body(Full::new(if req.method() == http::Method::HEAD {
            Bytes::new()
        } else {
            Bytes::from(text)
        }))
        .unwrap()
}
