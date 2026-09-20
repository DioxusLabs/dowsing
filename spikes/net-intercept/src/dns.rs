//! Minimal DNS synthesis: parse the question glibc's resolver sends, answer with an A/AAAA
//! record for a synthetic address, NXDOMAIN, or SERVFAIL.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::peer_model::DnsOutcome;

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;

/// The address every name resolves to when the peer model says `Resolves`.
pub const SYNTHETIC_V4: Ipv4Addr = Ipv4Addr::new(10, 66, 66, 1);
pub const SYNTHETIC_V6: Ipv6Addr = Ipv6Addr::new(0xfd66, 0, 0, 0, 0, 0, 0, 1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub id: u16,
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Raw question section (for copying into the reply).
    pub raw_question: Vec<u8>,
}

pub fn parse_query(pkt: &[u8]) -> Option<Question> {
    if pkt.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([pkt[0], pkt[1]]);
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        let len = *pkt.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        let label = pkt.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += len;
    }
    let qtype = u16::from_be_bytes([*pkt.get(pos)?, *pkt.get(pos + 1)?]);
    let qclass = u16::from_be_bytes([*pkt.get(pos + 2)?, *pkt.get(pos + 3)?]);
    let raw_question = pkt[12..pos + 4].to_vec();
    Some(Question {
        id,
        name: labels.join("."),
        qtype,
        qclass,
        raw_question,
    })
}

pub fn build_reply(q: &Question, outcome: DnsOutcome) -> Vec<u8> {
    let rcode: u16 = match outcome {
        DnsOutcome::Resolves => 0,
        DnsOutcome::NxDomain => 3,
        DnsOutcome::ServFail => 2,
    };
    let rdata: Option<Vec<u8>> = match (outcome, q.qtype) {
        (DnsOutcome::Resolves, TYPE_A) => Some(SYNTHETIC_V4.octets().to_vec()),
        (DnsOutcome::Resolves, TYPE_AAAA) => Some(SYNTHETIC_V6.octets().to_vec()),
        _ => None,
    };
    let mut out = Vec::with_capacity(64 + q.raw_question.len());
    out.extend_from_slice(&q.id.to_be_bytes());
    // QR=1, opcode 0, AA=0, TC=0, RD=1, RA=1, rcode.
    out.extend_from_slice(&(0x8180u16 | rcode).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(rdata.is_some() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&q.raw_question);
    if let Some(rdata) = rdata {
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&q.qtype.to_be_bytes());
        out.extend_from_slice(&q.qclass.to_be_bytes());
        out.extend_from_slice(&60u32.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(&[4, b'f', b'u', b'z', b'z', 7]);
        q.extend_from_slice(b"invalid");
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        let parsed = parse_query(&q).unwrap();
        assert_eq!(parsed.name, "fuzz.invalid");
        assert_eq!(parsed.qtype, TYPE_A);
        let reply = build_reply(&parsed, DnsOutcome::Resolves);
        assert_eq!(&reply[0..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 1);
        assert_eq!(&reply[reply.len() - 4..], &SYNTHETIC_V4.octets());
    }
}
