//! The demo protocol shared by the example targets: a length-prefixed frame stream
//! `[u16 len][u8 kind][payload]` with an injected bug in the "compressed" frame kind.

use crate::peer_model::{ByteSource, PayloadGen};

pub const KIND_PING: u8 = 0;
pub const KIND_TEXT: u8 = 1;
pub const KIND_COMPRESSED: u8 = 2;

/// The client's fixed decompression buffer.
pub const BUF: usize = 64;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stats {
    pub frames: usize,
    pub pings: usize,
    pub text_bytes: usize,
    pub expanded: usize,
}

/// Parse one frame body. `kind == KIND_COMPRESSED` carries `[u8 n][byte]` and expands `n`
/// copies of `byte` into a fixed 64-byte buffer without checking `n` (the injected bug).
pub fn handle_frame(kind: u8, payload: &[u8], stats: &mut Stats) -> Result<(), String> {
    stats.frames += 1;
    match kind {
        KIND_PING => {
            stats.pings += 1;
            Ok(())
        }
        KIND_TEXT => {
            stats.text_bytes += payload.len();
            Ok(())
        }
        KIND_COMPRESSED => {
            let [n, byte] = payload else {
                return Err(format!("compressed frame needs 2 bytes, got {}", payload.len()));
            };
            let mut out = [0u8; BUF];
            // BUG: no `n <= BUF` check.
            for i in 0..*n as usize {
                out[i] = *byte;
            }
            stats.expanded += *n as usize;
            Ok(())
        }
        other => Err(format!("unknown frame kind {other}")),
    }
}

/// Frame-aware peer payload: one whole frame per `Data` event. Kind is a `variant` (0 = ping is
/// the simplest), lengths are `variant`s, bytes are RNG bytes, so `cautious()` can simplify the
/// frame toward a ping and zero its bytes.
pub fn frame_payload() -> PayloadGen {
    frame_payload_with(|rng| rng.variant(4) as u8) // 3 = malformed kind
}

/// Like [`frame_payload`] but the kind is a raw RNG byte: only 1/256 of frames are compressed,
/// so the search has to learn the `kind == 2` comparison (trace-compares) to find the bug fast.
pub fn frame_payload_kind_byte() -> PayloadGen {
    frame_payload_with(|rng| rng.byte())
}

fn frame_payload_with(mut kind: impl FnMut(&mut dyn ByteSource) -> u8 + 'static) -> PayloadGen {
    Box::new(move |rng: &mut dyn ByteSource| {
        let kind = kind(rng);
        let body: Vec<u8> = match kind {
            KIND_PING => Vec::new(),
            KIND_COMPRESSED => vec![rng.byte(), rng.byte()],
            _ => {
                let len = rng.variant(BUF + 1);
                let mut b = vec![0u8; len];
                rng.fill(&mut b);
                b
            }
        };
        let len = (body.len() + 1) as u16;
        let mut frame = Vec::with_capacity(body.len() + 3);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.push(kind);
        frame.extend_from_slice(&body);
        frame
    })
}

/// Raw bytes instead of whole frames: harder for the fuzzer (frame boundaries must line up).
pub fn raw_payload() -> PayloadGen {
    crate::peer_model::random_payload()
}

/// Render a transcript line's data payload as frames for the report.
pub fn describe_frames(bytes: &[u8]) -> String {
    let mut out = Vec::new();
    let mut rest = bytes;
    while rest.len() >= 3 {
        let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        if len == 0 || rest.len() < 2 + len {
            break;
        }
        let kind = rest[2];
        let body = &rest[3..2 + len];
        out.push(match kind {
            KIND_PING => "Ping".to_string(),
            KIND_TEXT => format!("Text[{}]", body.len()),
            KIND_COMPRESSED if body.len() == 2 => format!("Compressed[n={}, b={:#04x}]", body[0], body[1]),
            _ => format!("Frame[kind={kind}, len={}]", body.len()),
        });
        rest = &rest[2 + len..];
    }
    if !rest.is_empty() {
        out.push(format!("+{} trailing bytes", rest.len()));
    }
    out.join(", ")
}
