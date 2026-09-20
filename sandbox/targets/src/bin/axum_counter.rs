//! An ordinary axum service: a counter with a check-then-act update, JSON endpoints and an
//! invariant route. Nothing here knows about the sandbox beyond the coverage
//! runtime's `init()` (which keeps the sancov callbacks linked): the fuzzer plays the HTTP
//! clients through the socket API and drives the runtime's threads.
//!
//! Bugs:
//! - `POST /inc` reads the counter under the lock, awaits an audit call (a stand-in for the
//!   round trip to an external service), and takes the lock again to write. Two handlers
//!   interleave in that gap and lose an update, which `GET /check` reports as a panic.
//! - `POST /inc_nowait` is the same without the await: the gap is a few dozen instructions
//!   between two atomics, and the interleaving needs the other worker thread to run the
//!   second handler inside it.
//! - `POST /sum` takes the first body frame and parses it as the whole JSON body. Correct as
//!   long as the request arrives in one TCP segment (always, over loopback); a split body is a
//!   500. `POST /echo` is a plain JSON round trip (400 on more than four tags).

use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Clone)]
struct App {
    counter: Arc<Mutex<u64>>,
    increments: Arc<AtomicU64>,
}

async fn audit(_v: u64) {
    tokio::time::sleep(Duration::from_millis(1)).await;
}

async fn inc(State(app): State<App>) -> String {
    let v = *app.counter.lock().await;
    audit(v).await;
    *app.counter.lock().await = v + 1;
    app.increments.fetch_add(1, Ordering::SeqCst);
    format!("{}\n", v + 1)
}

async fn inc_nowait(State(app): State<App>) -> String {
    let v = *app.counter.lock().await;
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

#[derive(Deserialize)]
struct Sum {
    xs: Vec<i64>,
}

async fn sum(body: Body) -> (StatusCode, String) {
    let mut frames = body.into_data_stream();
    let first = match frames.next().await {
        Some(Ok(bytes)) => bytes,
        _ => return (StatusCode::BAD_REQUEST, "empty body\n".into()),
    };
    match serde_json::from_slice::<Sum>(&first) {
        Ok(s) => (StatusCode::OK, format!("{}\n", s.xs.iter().sum::<i64>())),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("body was not one frame: {e}\n"),
        ),
    }
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
            .route("/inc_nowait", post(inc_nowait))
            .route("/check", get(check))
            .route("/echo", post(echo))
            .route("/sum", post(sum))
            .with_state(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await.unwrap();
        axum::serve(listener, router).await.unwrap();
    });
}
