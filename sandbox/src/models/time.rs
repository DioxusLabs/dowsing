//! Virtual time as the target sees it: clock reads answer from the scheduler's clock and
//! advance it by a tick; sleeps park the thread until the scheduler fires the deadline. The
//! clock itself belongs to the scheduler (`Sched::clock_ns`) because *when* it advances is a
//! schedule decision; this model is only the syscall surface over it.

use crate::{
    model::{Cx, Emu, Filter, Model, ModelId},
    ptrace::Regs,
    sched::ThreadState,
    world::Point,
};
use std::io;

const TIMER_ABSTIME: u64 = 1;

#[derive(Debug, Clone, Copy, Default)]
pub struct Time;

impl Model for Time {
    const ID: ModelId = ModelId::Time;
    const FILTER: Filter = Filter {
        always: &[
            libc::SYS_nanosleep,
            libc::SYS_clock_nanosleep,
            libc::SYS_clock_gettime,
            libc::SYS_gettimeofday,
            libc::SYS_time,
        ],
        vfd: &[],
    };

    fn syscall(&mut self, cx: &mut Cx, _thread: usize, regs: &Regs) -> io::Result<Emu> {
        let nr = regs.orig_rax as i64;
        Ok(match nr {
            n if n == libc::SYS_nanosleep || n == libc::SYS_clock_nanosleep => {
                let (req, absolute) = if n == libc::SYS_nanosleep {
                    (regs.rdi, false)
                } else {
                    (regs.rdx, regs.rsi & TIMER_ABSTIME != 0)
                };
                let dur = cx.read_timespec_ns(req)?;
                let deadline = if absolute {
                    dur
                } else {
                    cx.now().saturating_add(dur)
                };
                let seq = cx.sched.next_seq();
                Emu::Wait(ThreadState::Sleep { deadline, seq }, Point::Sleep)
            }
            n if n == libc::SYS_clock_gettime => {
                let ns = cx.sched.clock_read(regs.rdi as i32);
                cx.write_timespec(regs.rsi, ns)?;
                Emu::Stop(0, Point::Clock)
            }
            n if n == libc::SYS_gettimeofday => {
                let ns = cx.sched.clock_read(libc::CLOCK_REALTIME);
                if regs.rdi != 0 {
                    let mut buf = [0u8; 16];
                    buf[..8].copy_from_slice(&((ns / 1_000_000_000) as i64).to_ne_bytes());
                    buf[8..].copy_from_slice(&(((ns % 1_000_000_000) / 1000) as i64).to_ne_bytes());
                    cx.write_mem(regs.rdi, &buf)?;
                }
                Emu::Stop(0, Point::Clock)
            }
            n if n == libc::SYS_time => {
                let secs = (cx.sched.clock_read(libc::CLOCK_REALTIME) / 1_000_000_000) as i64;
                if regs.rdi != 0 {
                    cx.write_u64(regs.rdi, secs as u64)?;
                }
                Emu::Stop(secs, Point::Clock)
            }
            _ => Emu::Pass,
        })
    }
}
