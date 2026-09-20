//! Deterministic entropy: `getrandom` answers from a counter-seeded generator, so hash seeds,
//! random ports and backoff jitter are a function of the path, not of the host.

use crate::{
    model::{Cx, Emu, Filter, Model, ModelId},
    ptrace::Regs,
    world::Point,
};
use std::io;

#[derive(Debug, Clone, Default)]
pub struct Entropy {
    /// `getrandom` calls answered so far.
    pub seq: u64,
}

impl Entropy {
    /// The bytes of the next `getrandom(len)`.
    pub fn next_bytes(&mut self, len: usize) -> Vec<u8> {
        self.seq += 1;
        let mut bytes = vec![0u8; len];
        let mut s = self.seq.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        for b in &mut bytes {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            *b = s as u8;
        }
        bytes
    }
}

impl Model for Entropy {
    const ID: ModelId = ModelId::Entropy;
    const FILTER: Filter = Filter {
        always: &[libc::SYS_getrandom],
        vfd: &[],
    };

    fn syscall(&mut self, cx: &mut Cx, _thread: usize, regs: &Regs) -> io::Result<Emu> {
        if regs.orig_rax as i64 != libc::SYS_getrandom {
            return Ok(Emu::Pass);
        }
        let len = (regs.rsi as usize).min(4096);
        let bytes = self.next_bytes(len);
        cx.write_mem(regs.rdi, &bytes)?;
        Ok(Emu::Stop(len as i64, Point::Getrandom))
    }
}
