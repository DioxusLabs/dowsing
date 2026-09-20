//! Harness-side pieces shared by the demo example and the replay test: how `app.conf` is
//! generated from the `CaseRng`, the declared virtual tree, and how a target outcome is classified.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use fs_env_intercept::draw::pick;
use fs_env_intercept::{Content, Draw, Spec};

use super::demo_target;

/// `key=value` lines as a `sequence` so `cautious()` can delete whole lines; every value is a
/// `variant` (index 0 = simplest) so the minimized file reads naturally.
pub fn structured_config(draw: &mut dyn Draw) -> Vec<u8> {
    let mut out = Vec::new();
    draw.sequence(0..=4, &mut |_, draw| {
        let (_, key) = pick(draw, &["mode", "retries", "name", "seed", "# note", "bogus"]);
        match *key {
            "mode" => {
                let (_, value) = pick(draw, &["lenient", "strict", "fast", ""]);
                out.extend_from_slice(format!("mode={value}\n").as_bytes());
            }
            "retries" => {
                let value = draw.variant(300);
                out.extend_from_slice(format!("retries={value}\n").as_bytes());
            }
            "name" => {
                let value = draw.bytes(0..=6);
                out.extend_from_slice(b"name=");
                out.extend(value.iter().map(|b| b'a' + b % 26));
                out.push(b'\n');
            }
            "seed" => {
                let value = draw.variant(1 << 16);
                out.extend_from_slice(format!("seed={value}\n").as_bytes());
            }
            "# note" => out.extend_from_slice(b"# note\n"),
            _ => out.extend_from_slice(&draw.bytes(0..=8)),
        }
    });
    out
}

pub fn spec(raw: bool) -> Arc<Spec> {
    let content = if raw {
        Content::Random { max_len: 48 }
    } else {
        Content::Generate(Arc::new(structured_config))
    };
    Arc::new(
        Spec::new()
            .file("/etc/app/app.conf", content)
            .file("/var/lib/app/state.db", Content::Random { max_len: 16 })
            .dir("/var/lib/app", 2)
            .env("APP_MODE", vec![Some("lenient"), Some("strict"), None]),
    )
}

/// Run the target once and classify the outcome. The bug is a panic inside the target.
pub fn run_target() -> Result<demo_target::Summary, String> {
    match catch_unwind(AssertUnwindSafe(demo_target::run)) {
        Ok(result) => result,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "panic".to_string());
            Err(format!("PANIC: {msg}"))
        }
    }
}

pub fn is_bug(result: &Result<demo_target::Summary, String>) -> bool {
    matches!(result, Err(msg) if msg.starts_with("PANIC:"))
}
