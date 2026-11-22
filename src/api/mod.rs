//! The HTTP APIs, each served at the root and under `/api`, as Esplora
//! deployments usually are.

pub mod esplora;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

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
    pub mempool_tx: std::sync::mpsc::Sender<(Vec<u8>, crate::mempool::Source)>,
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
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or_else(|err| Err(ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{err}"))))
}

async fn status(axum::extract::State(state): axum::extract::State<AppState>) -> Json<serde_json::Value> {
    let status = state.status.lock().unwrap().clone();
    let usage: serde_json::Map<String, serde_json::Value> =
        state.store.disk_usage().into_iter().map(|(k, v)| (k.to_string(), v.into())).collect();
    Json(serde_json::json!({
        "network": state.store.chain.name(),
        "version": env!("CARGO_PKG_VERSION"),
        "peers": status.peers,
        "headers": status.headers,
        "indexed": status.indexed,
        "syncing": state.store.syncing(),
        "mempool": state.mempool.read().unwrap().len(),
        "disk_usage": usage,
    }))
}

pub fn router(state: AppState) -> Router {
    let apis = esplora::router();
    Router::new()
        .route("/status", get(status))
        .merge(apis.clone())
        .nest("/api", apis)
        .with_state(state)
        .layer(axum::middleware::from_fn(cors))
}

/// Lets any page read the API, as public Esplora servers do.
async fn cors(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, axum::http::HeaderValue::from_static("*"));
    response
}

pub async fn serve(
    addr: SocketAddr,
    state: AppState,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("serving the API on http://{addr}");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
        })
        .await?;
    Ok(())
}
