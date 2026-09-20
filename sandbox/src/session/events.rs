//! The ptrace event stream, and the syscalls the core answers itself: futex, clone, yield,
//! exit, the target runtime's marker, and the two the snapshot mechanism must see (`rseq`,
//! `munmap`). Everything else stopped by the filter belongs to a model.

use super::Session;
use crate::{
    ptrace::{self, Pid, Regs, WaitEvent},
    sched::Sched,
    shm::{MARKER_MAGIC, MARKER_SYSCALL, MARKER_VARIANT},
    world::*,
};
use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
};

static ALARM_FIRED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_alarm(_sig: libc::c_int) {
    ALARM_FIRED.store(true, Ordering::SeqCst);
}

pub(super) fn install_alarm_handler() {
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_alarm as extern "C" fn(libc::c_int) as usize;
        action.sa_flags = 0;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGALRM, &action, std::ptr::null_mut());
    }
}

const CRASH_SIGNALS: &[i32] = &[
    libc::SIGSEGV,
    libc::SIGBUS,
    libc::SIGILL,
    libc::SIGFPE,
    libc::SIGABRT,
    libc::SIGSYS,
];

const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_WAIT_BITSET: u64 = 9;
const FUTEX_WAKE_BITSET: u64 = 10;
const FUTEX_CLOCK_REALTIME: u64 = 256;
const FUTEX_CMD_MASK: u64 = !(128 | 256);
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;

impl Session {
    pub(super) fn wait_and_handle(&mut self) -> io::Result<()> {
        unsafe {
            ALARM_FIRED.store(false, Ordering::SeqCst);
            libc::alarm(self.opts.watchdog.as_secs().max(1) as u32);
        }
        let event = ptrace::wait_any();
        unsafe {
            libc::alarm(0);
        }
        let event = match event {
            Ok(event) => event,
            Err(err)
                if err.kind() == io::ErrorKind::Interrupted
                    && ALARM_FIRED.load(Ordering::SeqCst) =>
            {
                return self.watchdog_fired();
            }
            Err(err) => return Err(err),
        };
        self.stops += 1;
        self.handle_event(event)
    }

    /// Stop the running thread where it is and end the run with `Timeout`.
    fn watchdog_fired(&mut self) -> io::Result<()> {
        let Some(index) = self.world.sched.current else {
            return Err(io::Error::other("watchdog fired with no running thread"));
        };
        let tid = self.world.sched.threads[index].tid;
        ptrace::interrupt(tid)?;
        match ptrace::wait_pid(tid)? {
            WaitEvent::Event { .. }
            | WaitEvent::GroupStop { .. }
            | WaitEvent::Signal { .. }
            | WaitEvent::Syscall { .. } => {}
            other => return Err(io::Error::other(format!("interrupt: unexpected {other:?}"))),
        }
        // A PTRACE_INTERRUPT stop inside a syscall would resume that syscall; the skipped shape
        // keeps the thread restorable.
        let mut regs = ptrace::getregs(tid)?;
        if regs.orig_rax != u64::MAX {
            regs.orig_rax = u64::MAX;
            regs.rax = -(libc::EINTR as i64) as u64;
            ptrace::setregs(tid, &regs)?;
        }
        self.world.sched.threads[index].state = ThreadState::Stopped;
        self.world.sched.current = None;
        self.record(index, Point::Preempt);
        self.world.outcome = Some(Outcome::Timeout);
        Ok(())
    }

    fn handle_event(&mut self, event: WaitEvent) -> io::Result<()> {
        match event {
            WaitEvent::Event { pid, event } if event == libc::PTRACE_EVENT_SECCOMP => {
                let index = self.world.sched.thread_index(pid).ok_or_else(|| {
                    io::Error::other(format!("seccomp stop from unknown tid {pid}"))
                })?;
                self.handle_seccomp(index)
            }
            WaitEvent::Event { pid, event } if event == libc::PTRACE_EVENT_CLONE => {
                let parent = self.world.sched.thread_index(pid).ok_or_else(|| {
                    io::Error::other(format!("clone event from unknown tid {pid}"))
                })?;
                let child_tid = ptrace::geteventmsg(pid)? as Pid;
                let already_stopped =
                    if let Some(pos) = self.orphan_stops.iter().position(|t| *t == child_tid) {
                        self.orphan_stops.swap_remove(pos);
                        true
                    } else {
                        false
                    };
                if !already_stopped {
                    match ptrace::wait_pid(child_tid)? {
                        WaitEvent::Event { .. } | WaitEvent::GroupStop { .. } => {}
                        other => {
                            return Err(io::Error::other(format!(
                                "unexpected first event from new thread {child_tid}: {other:?}"
                            )));
                        }
                    }
                    self.stops += 1;
                }
                // Run the parent to its syscall-exit stop so `rax` holds the child tid and the
                // stop has the uniform "continue at rip" shape.
                ptrace::syscall(pid, 0)?;
                loop {
                    match ptrace::wait_pid(pid)? {
                        WaitEvent::Syscall { .. } => break,
                        WaitEvent::Event { .. } | WaitEvent::GroupStop { .. } => {
                            ptrace::syscall(pid, 0)?
                        }
                        other => {
                            return Err(io::Error::other(format!(
                                "clone exit: unexpected {other:?}"
                            )));
                        }
                    }
                }
                self.stops += 1;
                let mut regs = ptrace::getregs(pid)?;
                regs.orig_rax = u64::MAX;
                ptrace::setregs(pid, &regs)?;
                let sched = &mut self.world.sched;
                let ctid = std::mem::take(&mut sched.threads[parent].pending_clone_ctid);
                let child_index = sched.threads.len();
                let mut child = Thread::new(child_tid);
                child.clear_tid = ctid;
                sched.threads.push(child);
                sched.threads[parent].state = ThreadState::Stopped;
                sched.current = None;
                self.record(parent, Point::Clone);
                self.record(child_index, Point::ThreadStart);
                Ok(())
            }
            WaitEvent::Event { pid, event } if event == libc::PTRACE_EVENT_EXIT => {
                // Only reachable if something bypassed our exit emulation; report and let it go.
                self.uncontrolled.push(format!("real exit of tid {pid}"));
                ptrace::cont(pid, 0)
            }
            WaitEvent::Event { pid, event } if event == libc::PTRACE_EVENT_STOP => {
                let sched = &mut self.world.sched;
                match sched.thread_index(pid) {
                    Some(index) => {
                        if sched.threads[index].state == ThreadState::Running {
                            sched.threads[index].state = ThreadState::Stopped;
                            if sched.current == Some(index) {
                                sched.current = None;
                            }
                        }
                    }
                    None => self.orphan_stops.push(pid),
                }
                Ok(())
            }
            WaitEvent::Event { pid, event } => {
                self.uncontrolled
                    .push(format!("ptrace event {event} on tid {pid}"));
                ptrace::cont(pid, 0)
            }
            WaitEvent::Syscall { pid } => ptrace::cont(pid, 0),
            WaitEvent::GroupStop { pid, .. } => ptrace::cont(pid, 0),
            WaitEvent::Signal { pid, sig } => {
                let Some(index) = self.world.sched.thread_index(pid) else {
                    return ptrace::cont(pid, sig);
                };
                if CRASH_SIGNALS.contains(&sig) {
                    if self.opts.verbose {
                        let regs = ptrace::getregs(pid)?;
                        let stderr = self.take_stderr();
                        eprintln!(
                            "[sandbox] T{index} tid {pid} signal {sig} at rip {:#x} orig_rax {} rax {:#x} rsp {:#x}\n{stderr}",
                            regs.rip, regs.orig_rax as i64, regs.rax, regs.rsp
                        );
                    }
                    // Not delivered: the thread stays stopped and restorable.
                    self.world.sched.threads[index].state = ThreadState::Stopped;
                    self.world.sched.current = None;
                    self.normalize_stop(pid)?;
                    self.record(index, Point::Signal(sig));
                    self.world.outcome = Some(Outcome::Signaled(sig));
                    Ok(())
                } else if sig == libc::SIGCONT || sig == libc::SIGSTOP || sig == libc::SIGTRAP {
                    ptrace::cont(pid, 0)
                } else {
                    ptrace::cont(pid, sig)
                }
            }
            WaitEvent::Exited { pid, code } => self.process_gone(pid, Outcome::Exited(code)),
            WaitEvent::Killed { pid, sig } => self.process_gone(pid, Outcome::Signaled(sig)),
        }
    }

    fn process_gone(&mut self, pid: Pid, outcome: Outcome) -> io::Result<()> {
        if pid == self.leader {
            self.alive = false;
            return Err(io::Error::other(format!(
                "target process died ({outcome}); the session cannot be restored"
            )));
        }
        let sched = &mut self.world.sched;
        if let Some(index) = sched.thread_index(pid) {
            self.uncontrolled
                .push(format!("thread {index} died: {outcome}"));
            sched.threads[index].state = ThreadState::Parked;
            if sched.current == Some(index) {
                sched.current = None;
            }
        }
        Ok(())
    }

    /// If `tid` is stopped inside a syscall entry (a signal arrived at a seccomp stop), turn
    /// the stop into the skipped shape.
    fn normalize_stop(&mut self, tid: Pid) -> io::Result<()> {
        let mut regs = ptrace::getregs(tid)?;
        if regs.orig_rax != u64::MAX {
            regs.orig_rax = u64::MAX;
            ptrace::setregs(tid, &regs)?;
        }
        Ok(())
    }

    fn handle_seccomp(&mut self, index: usize) -> io::Result<()> {
        let tid = self.world.sched.threads[index].tid;
        let mut regs = ptrace::getregs(tid)?;
        if self.syscall_insn == 0 {
            let insn = regs.rip - 2;
            let mut bytes = [0u8; 2];
            ptrace::read_mem(self.leader, insn, &mut bytes)?;
            if bytes == [0x0f, 0x05] {
                self.syscall_insn = insn;
            }
        }
        let nr = regs.orig_rax as i64;
        match nr {
            n if n == libc::SYS_futex => self.handle_futex(index, &mut regs),
            n if n == libc::SYS_clone || n == libc::SYS_clone3 => {
                let ctid = if n == libc::SYS_clone {
                    if regs.rdi & CLONE_CHILD_CLEARTID != 0 {
                        regs.r10
                    } else {
                        0
                    }
                } else {
                    let flags = ptrace::read_u64(self.leader, regs.rdi)?;
                    if flags & CLONE_CHILD_CLEARTID != 0 {
                        ptrace::read_u64(self.leader, regs.rdi + 16)?
                    } else {
                        0
                    }
                };
                self.world.sched.threads[index].pending_clone_ctid = ctid;
                ptrace::cont(tid, 0)
            }
            n if n == libc::SYS_sched_yield => {
                self.skip_syscall(tid, &mut regs, 0)?;
                self.stop_here(index, Point::Yield);
                Ok(())
            }
            n if n == libc::SYS_sched_getaffinity => {
                if regs.rsi < 8 {
                    self.skip_syscall(tid, &mut regs, -(libc::EINVAL as i64))?;
                } else {
                    let mask: u64 = if self.opts.cpus >= 64 {
                        u64::MAX
                    } else {
                        (1u64 << self.opts.cpus) - 1
                    };
                    ptrace::write_u64(self.leader, regs.rdx, mask)?;
                    self.skip_syscall(tid, &mut regs, 8)?;
                }
                ptrace::cont(tid, 0)
            }
            n if n == MARKER_SYSCALL && regs.rdi == MARKER_MAGIC => match regs.rsi {
                MARKER_VARIANT => {
                    let nchoices = (regs.rdx as u32).max(1);
                    self.skip_syscall(tid, &mut regs, 0)?;
                    self.world.sched.threads[index].state = ThreadState::Stopped;
                    self.world.sched.current = None;
                    self.record(index, Point::Variant);
                    if nchoices >= 2 {
                        self.world.pending = Some(Pending::Variant {
                            thread: index,
                            n: nchoices,
                        });
                    }
                    Ok(())
                }
                _ => {
                    self.skip_syscall(tid, &mut regs, 0)?;
                    self.stop_here(index, Point::Preempt);
                    Ok(())
                }
            },
            // Refused: an rseq registration is per-task kernel state the snapshot cannot carry,
            // and the kernel would write cpu ids into the TCB behind our back. glibc treats
            // ENOSYS as "old kernel" and never retries.
            n if n == libc::SYS_rseq => {
                self.skip_syscall(tid, &mut regs, -(libc::ENOSYS as i64))?;
                ptrace::cont(tid, 0)
            }
            // Memory that exists in the current snapshot is kept (as PROT_NONE) instead of
            // unmapped, so restoring it is an mprotect plus the pages dirtied since, not a
            // rewrite of the whole range. Costs address space until the process exits.
            n if n == libc::SYS_munmap => {
                if self.retained(regs.rdi, regs.rsi) {
                    regs.orig_rax = libc::SYS_mprotect as u64;
                    regs.rdx = libc::PROT_NONE as u64;
                    ptrace::setregs(tid, &regs)?;
                }
                ptrace::cont(tid, 0)
            }
            n if n == libc::SYS_exit => {
                // Emulate the kernel side of thread exit and freeze the task.
                self.skip_syscall(tid, &mut regs, 0)?;
                self.world.sched.threads[index].state = ThreadState::Parked;
                self.world.sched.current = None;
                self.record(index, Point::Exit);
                let ctid = self.world.sched.threads[index].clear_tid;
                if ctid != 0 {
                    ptrace::write_u32(self.leader, ctid, 0)?;
                    self.wake_futex(ctid, u32::MAX, usize::MAX);
                }
                Ok(())
            }
            n if n == libc::SYS_exit_group => {
                self.skip_syscall(tid, &mut regs, 0)?;
                self.world.sched.threads[index].state = ThreadState::Stopped;
                self.world.sched.current = None;
                self.record(index, Point::ExitGroup);
                self.world.outcome = Some(Outcome::Exited((regs.rdi & 0xff) as i32));
                Ok(())
            }
            n => match Self::model_for(n) {
                Some(model) => self.model_syscall(model, index, regs),
                None => {
                    self.uncontrolled
                        .push(format!("syscall {n} passed through on T{index}"));
                    ptrace::cont(tid, 0)
                }
            },
        }
    }

    /// Wake up to `max` emulated waiters on `addr` matching `mask`, oldest first. Returns how many.
    fn wake_futex(&mut self, addr: u64, mask: u32, max: usize) -> usize {
        let mut waiters: Vec<(u64, usize)> = self
            .world
            .sched
            .threads
            .iter()
            .enumerate()
            .filter_map(|(i, t)| match t.state {
                ThreadState::FutexWait {
                    addr: waddr,
                    bitset,
                    seq,
                    ..
                } if waddr == addr && (bitset & mask) != 0 => Some((seq, i)),
                _ => None,
            })
            .collect();
        waiters.sort();
        let woken: Vec<usize> = waiters.into_iter().take(max).map(|(_, i)| i).collect();
        for waiter in &woken {
            self.world.sched.threads[*waiter].state = ThreadState::Stopped;
            self.record(*waiter, Point::FutexWoken);
        }
        woken.len()
    }

    /// Kernel-side writes to futex words (none expected now that thread exit is emulated), plus
    /// wake-ups we emulate ourselves: wake waiters whose word no longer matches.
    pub(super) fn recheck_futex_words(&mut self) -> io::Result<bool> {
        let mut woke = false;
        for i in 0..self.world.sched.threads.len() {
            if let ThreadState::FutexWait { addr, val, .. } = self.world.sched.threads[i].state {
                let value = ptrace::read_u32(self.leader, addr)?;
                if value != val {
                    self.set_return(i, 0)?;
                    self.world.sched.threads[i].state = ThreadState::Stopped;
                    self.record(i, Point::FutexWoken);
                    woke = true;
                }
            }
        }
        Ok(woke)
    }

    fn handle_futex(&mut self, index: usize, regs: &mut Regs) -> io::Result<()> {
        let tid = self.world.sched.threads[index].tid;
        let addr = regs.rdi;
        let op = regs.rsi;
        let val = regs.rdx as u32;
        let timeout = regs.r10;
        let val3 = regs.r9 as u32;
        match op & FUTEX_CMD_MASK {
            FUTEX_WAIT | FUTEX_WAIT_BITSET => {
                let current = ptrace::read_u32(self.leader, addr)?;
                if current != val {
                    self.skip_syscall(tid, regs, -(libc::EAGAIN as i64))?;
                    self.stop_here(index, Point::FutexNoWait);
                    return Ok(());
                }
                let bitset_op = op & FUTEX_CMD_MASK == FUTEX_WAIT_BITSET;
                let deadline = if timeout == 0 {
                    None
                } else {
                    let ts = self.cx().read_timespec_ns(timeout)?;
                    Some(if bitset_op {
                        // Absolute; realtime deadlines are converted to the monotonic clock.
                        if op & FUTEX_CLOCK_REALTIME != 0 {
                            Sched::realtime_to_monotonic(ts)
                        } else {
                            ts
                        }
                    } else {
                        self.world.sched.clock_ns.saturating_add(ts)
                    })
                };
                self.skip_syscall(tid, regs, 0)?;
                let seq = self.world.sched.next_seq();
                self.world.sched.threads[index].state = ThreadState::FutexWait {
                    addr,
                    val,
                    bitset: if bitset_op { val3 } else { u32::MAX },
                    deadline,
                    seq,
                };
                self.world.sched.current = None;
                self.record(index, Point::FutexWait);
                Ok(())
            }
            FUTEX_WAKE | FUTEX_WAKE_BITSET => {
                let mask = if op & FUTEX_CMD_MASK == FUTEX_WAKE_BITSET {
                    val3
                } else {
                    u32::MAX
                };
                self.world.sched.threads[index].state = ThreadState::Stopped;
                self.world.sched.current = None;
                self.record(index, Point::FutexWake);
                let woken = self.wake_futex(addr, mask, val as usize);
                self.skip_syscall(tid, regs, woken as i64)?;
                Ok(())
            }
            other => {
                self.uncontrolled
                    .push(format!("futex op {other} passed through on T{index}"));
                ptrace::cont(tid, 0)
            }
        }
    }
}
