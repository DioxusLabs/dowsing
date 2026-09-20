//! `getpid`, `gettid`, `uname`, `sysinfo`: variants over interesting sets, index 0 realistic.
//! Each value is drawn once per case so repeated calls agree.

use crate::draw::pick;
use crate::notif::Notification;
use crate::supervisor::{Answer, Ctx, Session};

pub struct IdentityState {
    real_pid: u32,
    real_tid: u32,
    pid: Option<u32>,
    tid: Option<u32>,
    uname: Option<usize>,
    sysinfo: Option<(u64, u16)>,
    pub non_default: usize,
}

impl IdentityState {
    pub fn new(real_pid: u32, real_tid: u32) -> Self {
        Self {
            real_pid,
            real_tid,
            pid: None,
            tid: None,
            uname: None,
            sysinfo: None,
            non_default: 0,
        }
    }
}

pub fn handle(session: &mut Session, ctx: &Ctx, n: &Notification) -> Answer {
    match n.nr {
        libc::SYS_getpid => {
            let pid = match session.identity.pid {
                Some(pid) => pid,
                None => {
                    let (index, choice) = pick(session.draw.as_mut(), &session.spec.identity.pids);
                    if index != 0 {
                        session.identity.non_default += 1;
                    }
                    let pid = choice.unwrap_or(session.identity.real_pid);
                    session.identity.pid = Some(pid);
                    pid
                }
            };
            Answer::Ret(i64::from(pid))
        }
        libc::SYS_gettid => {
            let tid = match session.identity.tid {
                Some(tid) => tid,
                None => {
                    let (index, choice) = pick(session.draw.as_mut(), &session.spec.identity.tids);
                    if index != 0 {
                        session.identity.non_default += 1;
                    }
                    // Other threads of the target keep their real tid.
                    let tid = choice.unwrap_or(session.identity.real_tid);
                    session.identity.tid = Some(tid);
                    tid
                }
            };
            if ctx.tid != session.identity.real_tid {
                return Answer::Continue;
            }
            Answer::Ret(i64::from(tid))
        }
        libc::SYS_uname => {
            let index = match session.identity.uname {
                Some(index) => index,
                None => {
                    let (index, _) = pick(session.draw.as_mut(), &session.spec.identity.unames);
                    if index != 0 {
                        session.identity.non_default += 1;
                    }
                    session.identity.uname = Some(index);
                    index
                }
            };
            let uname = &session.spec.identity.unames[index];
            // SAFETY: utsname is plain old data.
            let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
            fill(&mut uts.sysname, &uname.sysname);
            fill(&mut uts.nodename, &uname.nodename);
            fill(&mut uts.release, &uname.release);
            fill(&mut uts.version, &uname.version);
            fill(&mut uts.machine, &uname.machine);
            fill(&mut uts.domainname, &uname.domainname);
            write_struct(session, ctx, n.args[0], &uts)
        }
        libc::SYS_sysinfo => {
            let (total_ram, procs) = match session.identity.sysinfo {
                Some(values) => values,
                None => {
                    let (ri, ram) = pick(session.draw.as_mut(), &session.spec.identity.total_ram);
                    let (pi, procs) = pick(session.draw.as_mut(), &session.spec.identity.procs);
                    session.identity.non_default += usize::from(ri != 0) + usize::from(pi != 0);
                    session.identity.sysinfo = Some((*ram, *procs));
                    (*ram, *procs)
                }
            };
            // SAFETY: sysinfo is plain old data; the real call fills the fields we do not model.
            let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
            // SAFETY: valid pointer.
            unsafe { libc::sysinfo(&mut info) };
            info.mem_unit = 1;
            info.totalram = total_ram;
            info.freeram = info.freeram.min(total_ram);
            info.procs = procs;
            write_struct(session, ctx, n.args[0], &info)
        }
        _ => Answer::Continue,
    }
}

fn fill(field: &mut [libc::c_char; 65], value: &str) {
    for (dst, src) in field.iter_mut().zip(value.bytes().take(64)) {
        *dst = src as libc::c_char;
    }
}

pub fn write_struct<T>(session: &mut Session, ctx: &Ctx, addr: u64, value: &T) -> Answer {
    // SAFETY: T is plain old data viewed as bytes.
    let bytes = unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
    };
    match ctx.write(&session.mem, addr, bytes) {
        Ok(()) => Answer::Ret(0),
        Err(err) => Answer::Errno(err.raw_os_error().unwrap_or(libc::EFAULT)),
    }
}
