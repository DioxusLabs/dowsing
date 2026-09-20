//! An ordinary axum service: a counter with a check-then-act update across an `.await`, a JSON
//! endpoint, and an invariant route. Nothing here knows about the sandbox beyond the coverage
//! runtime's `init()` (which keeps the sancov callbacks linked): the fuzzer plays the HTTP
//! clients through the socket API and drives the runtime's threads.
//!
//! Bug: two concurrent `POST /inc` requests can lose an update (the read and the write are
//! separated by an await point while the lock is released), which `GET /check` then reports as
//! a panic. `POST /echo` is a plain JSON round trip (400 on more than four tags) so the corpus
//! has a route that exercises the body parser without failing.

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::Mutex;

#[derive(Clone)]
struct App {
    counter: Arc<Mutex<u64>>,
    increments: Arc<AtomicU64>,
}

async fn inc(State(app): State<App>) -> String {
    let v = *app.counter.lock().await;
    // Simulate some async work between the read and the write.
    tokio::task::yield_now().await;
    *app.counter.lock().await = v + 1;
    app.increments.fetch_add(1, Ordering::SeqCst);
    format!("{}\n", v + 1)
}

async fn check(State(app): State<App>) -> String {
    let counter = *app.counter.lock().await;
    let increments = app.increments.load(Ordering::SeqCst);
    assert_eq!(counter, increments, "lost update: counter {counter} != increments {increments}");
    format!("ok {counter}\n")
}

#[derive(Deserialize, Serialize)]
struct Echo {
    name: String,
    #[serde(default)]
    tags: Vec<String>,
}

async fn echo(Json(body): Json<Echo>) -> (StatusCode, Json<Echo>) {
    let status = if body.tags.len() > 4 {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    (status, Json(body))
}

async fn health() -> &'static str {
    "ok\n"
}

fn main() {
    dowsing_target_rt::init();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let app = App {
            counter: Arc::new(Mutex::new(0)),
            increments: Arc::new(AtomicU64::new(0)),
        };
        let router = Router::new()
            .route("/", get(health))
            .route("/inc", post(inc))
            .route("/check", get(check))
            .route("/echo", post(echo))
            .with_state(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await.unwrap();
        axum::serve(listener, router).await.unwrap();
    });
}
