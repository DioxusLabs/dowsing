//! HTTP/1.x framing: headers terminated by an empty line, body as long as `Content-Length`
//! says or chunked to a zero chunk. A 5xx status is a failure of the target.

use super::Protocol;
use crate::world::Outcome;

#[derive(Debug, Clone, Copy, Default)]
pub struct Http1;

impl Protocol for Http1 {
    fn request_complete(&self, req: &[u8]) -> bool {
        message_complete(req)
    }

    fn response_complete(&self, resp: &[u8]) -> bool {
        resp.starts_with(b"HTTP/") && message_complete(resp)
    }

    fn verdict(&self, resp: &[u8]) -> Option<Outcome> {
        status(resp)
            .filter(|c| *c >= 500)
            .map(|c| Outcome::Protocol(format!("http {c}")))
    }
}

fn message_complete(msg: &[u8]) -> bool {
    let Some(end) = find(msg, b"\r\n\r\n") else {
        return false;
    };
    let head = &msg[..end];
    let body = &msg[end + 4..];
    if let Some(len) = header_usize(head, b"content-length:") {
        return body.len() >= len;
    }
    if header_contains(head, b"transfer-encoding:", b"chunked") {
        return find(body, b"0\r\n\r\n").is_some();
    }
    true
}

/// Status code of the response line starting `bytes`.
pub fn status(bytes: &[u8]) -> Option<u16> {
    let rest = bytes.strip_prefix(b"HTTP/1.")?;
    let rest = rest.get(2..5)?;
    std::str::from_utf8(rest).ok()?.parse().ok()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn header_lines(head: &[u8]) -> impl Iterator<Item = &[u8]> {
    head.split(|b| *b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
}

fn header_usize(head: &[u8], name: &[u8]) -> Option<usize> {
    header_lines(head).find_map(|l| {
        let lower: Vec<u8> = l.to_ascii_lowercase();
        let v = lower.strip_prefix(name)?;
        std::str::from_utf8(v).ok()?.trim().parse().ok()
    })
}

fn header_contains(head: &[u8], name: &[u8], value: &[u8]) -> bool {
    header_lines(head).any(|l| {
        let lower: Vec<u8> = l.to_ascii_lowercase();
        lower
            .strip_prefix(name)
            .is_some_and(|v| find(v, value).is_some())
    })
}
