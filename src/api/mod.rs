//! The HTTP APIs, each served at the root and under `/api`, as Esplora
//! deployments usually are.

pub mod blindbit;
pub mod blockbook;
pub mod esplora;

pub(crate) use esplora::{Ctx, Found, History, ScriptRef, is_script, mempool_activity};

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use crate::node::Status;
use crate::store::Store;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub status: Arc<Mutex<Status>>,
    pub mempool: crate::mempool::Shared,
    /// Where transactions sent to the API go to be checked.
    pub mempool_tx: crate::mempool::Submit,
    pub prices: crate::prices::Shared,
}

/// An error to answer with: a status and plain text, as Esplora does.
#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub String);

impl ApiError {
    pub fn not_found(message: &str) -> ApiError {
        ApiError(StatusCode::NOT_FOUND, message.into())
    }

    pub fn bad_request(message: &str) -> ApiError {
        ApiError(StatusCode::BAD_REQUEST, message.into())
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> ApiError {
        tracing::error!("serving a request: {err:#}");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Internal error".into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, [(axum::http::header::CONTENT_TYPE, "text/plain")], self.1).into_response()
    }
}

/// Runs `f`, which reads the store, on a thread that may block.
pub async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    // Held until it's done, even if the request's given up on.
    let turn = queries().acquire_owned().await.expect("the semaphore is never closed");
    tokio::task::spawn_blocking(move || {
        let _turn = turn;
        f()
    })
    .await
    .unwrap_or_else(|err| {
        tracing::error!("serving a request: {err}");
        Err(ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Internal error".into()))
    })
}

async fn status(axum::extract::State(state): axum::extract::State<AppState>) -> Json<serde_json::Value> {
    let status = state.status.lock().unwrap().clone();
    let usage: serde_json::Map<String, serde_json::Value> =
        state.store.disk_usage().into_iter().map(|(k, v)| (k.to_string(), v.into())).collect();
    let mempool_stats = {
        let mempool = state.mempool.read().unwrap();
        serde_json::json!({
            "accepted": mempool.stats.accepted,
            "refused": mempool.stats.refused,
            "orphaned": mempool.stats.orphaned,
            "orphans": mempool.stats.orphans,
        })
    };
    Json(serde_json::json!({
        "network": state.store.chain.name(),
        "version": env!("CARGO_PKG_VERSION"),
        "peers": status.peers,
        "headers": status.headers,
        "indexed": status.indexed,
        "syncing": state.store.syncing(),
        "mempool": state.mempool.read().unwrap().len(),
        "mempool_stats": mempool_stats,
        "disk_usage": usage,
    }))
}

/// Which APIs to serve besides Esplora's.
#[derive(Debug, Clone, Copy, Default)]
pub struct Extras {
    pub blockbook: bool,
    pub blindbit: bool,
}

/// Esplora's API, at the root and under `/api`, and the others asked for.
pub fn router(state: AppState, extras: Extras) -> Router {
    let apis = esplora::router();
    let mut router = Router::new().route("/status", get(status)).merge(apis.clone()).nest("/api", apis);
    if extras.blockbook {
        router = router.merge(blockbook::router());
    }
    if extras.blindbit {
        router = router.merge(blindbit::router());
    }
    router.with_state(state).layer(axum::middleware::from_fn(cors))
}

/// Lets any page read the API, as public Esplora servers do.
async fn cors(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, axum::http::HeaderValue::from_static("*"));
    response
}

/// The most connections served at once.
const MAX_CONNECTIONS: usize = 1024;
/// The most requests reading the store at once; more wait their turn.
const MAX_QUERIES: usize = 64;
/// How long a client may take to send a request's headers.
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a request may take to be answered.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

fn queries() -> Arc<tokio::sync::Semaphore> {
    static QUERIES: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    QUERIES.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_QUERIES))).clone()
}

async fn time_out(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    match tokio::time::timeout(REQUEST_TIMEOUT, next.run(request)).await {
        Ok(response) => response,
        Err(_) => ApiError(StatusCode::SERVICE_UNAVAILABLE, "Timed out".into()).into_response(),
    }
}

pub async fn serve(
    addr: SocketAddr,
    state: AppState,
    extras: Extras,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    use hyper_util::rt::{TokioIo, TokioTimer};
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("serving the API on http://{addr}");
    let app = router(state, extras).layer(axum::middleware::from_fn(time_out));
    let connections = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(err) => {
                    // Out of file descriptors, most likely: wait for some to close.
                    tracing::warn!("accepting an HTTP connection: {err}");
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    continue;
                }
            },
            _ = shutdown.changed() => return Ok(()),
        };
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            tracing::debug!("too many HTTP connections: closing {peer}'s");
            continue;
        };
        let service = hyper_util::service::TowerToHyperService::new(app.clone());
        tokio::spawn(async move {
            let connection = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_TIMEOUT)
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades();
            if let Err(err) = connection.await {
                tracing::debug!("HTTP client {peer}: {err}");
            }
            drop(permit);
        });
    }
}
