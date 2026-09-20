//! The supervisor: one epoll loop per sandbox that serves seccomp notifications from the filtered
//! fuzz thread (and anything it spawns or forks).
//!
//! Only the `Session` decides anything; with no active case every trapped syscall is answered with
//! `SECCOMP_USER_NOTIF_FLAG_CONTINUE`. This is the loop the network/time/scheduler spikes would
//! plug into: each of them adds fds to the same epoll set (sockets, timerfds, pidfds) and handles
//! its own syscall numbers in `dispatch`, holding a `Pending` notification instead of answering
//! immediately when it wants to park the calling thread.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::bpf;
use crate::draw::{Draw, RngDraw};
use crate::mem::TargetMem;
use crate::notif::{self, Notification};
use crate::spec::Spec;
use crate::vfs::Vfs;
use crate::{entropy, fs, identity};
use iterator_fuzz::coverage::CoverageCapture;
use iterator_fuzz::{CaseCost, CaseRng};

/// What the supervisor tells the kernel to do with a trapped syscall.
pub enum Answer {
    Continue,
    Ret(i64),
    Errno(i32),
    /// Install `fd` into the target (at `newfd` if given) and return the new fd number. `fd` is
    /// owned by the supervisor and closed after the ioctl.
    AddFd {
        fd: i32,
        newfd: Option<u32>,
        cloexec: bool,
    },
}

#[derive(Debug, Default, Clone)]
pub struct CaseReport {
    pub trapped: u64,
    pub continued: u64,
    pub answered: u64,
    pub virtual_opens: u64,
    pub entropy_bytes: u64,
    pub per_tid: HashMap<u32, u64>,
    pub unsupported: Vec<String>,
    pub send_retries: u64,
    pub materialized_bytes: usize,
    pub non_default_variants: usize,
    pub touched: usize,
    pub draw_bytes: usize,
    pub trace_overflow: bool,
    /// Virtual files the target opened, with their materialized bytes.
    pub files: Vec<(PathBuf, Vec<u8>)>,
    pub applied_env: Vec<(String, Option<String>)>,
}

impl CaseReport {
    /// `materialized bytes + 16 x non-default variants`.
    pub fn cost(&self) -> CaseCost {
        CaseCost::new(self.materialized_bytes + 16 * self.non_default_variants)
    }

    /// True when the case should be excluded from feedback.
    pub fn should_discard(&self) -> bool {
        self.trace_overflow || !self.unsupported.is_empty()
    }
}

pub struct Session {
    pub draw: Box<dyn Draw>,
    pub spec: Arc<Spec>,
    pub vfs: Vfs,
    pub mem: TargetMem,
    pub identity: identity::IdentityState,
    pub entropy: entropy::EntropyState,
    pub report: CaseReport,
}

impl Session {
    pub fn unsupported(&mut self, what: impl Into<String>) -> Answer {
        self.report.unsupported.push(what.into());
        Answer::Errno(libc::ENOSYS)
    }
}

struct Shared {
    session: Mutex<Option<Session>>,
    listener: i32,
}

/// A sandbox bound to the thread that called [`Sandbox::install`].
pub struct Sandbox {
    shared: Arc<Shared>,
    fuzz_tid: u32,
    saved_env: Vec<(String, Option<std::ffi::OsString>)>,
}

impl Sandbox {
    /// Install the filter on the calling thread and start the supervisor. Irreversible for this
    /// thread; every thread spawned from it afterwards is filtered too.
    pub fn install() -> io::Result<Self> {
        let (tx, rx) = mpsc::channel::<Arc<Shared>>();
        // The supervisor must be spawned before the filter exists so it is unfiltered.
        let supervisor = thread::Builder::new()
            .name("dowsing-supervisor".into())
            .spawn(move || {
                let shared = rx.recv().expect("sandbox handed over");
                run_loop(shared);
            })?;
        let listener = bpf::install()?;
        let shared = Arc::new(Shared {
            session: Mutex::new(None),
            listener,
        });
        tx.send(Arc::clone(&shared))
            .map_err(|_| io::Error::other("supervisor thread died"))?;
        drop(supervisor);
        // SAFETY: plain syscall.
        let fuzz_tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
        Ok(Self {
            shared,
            fuzz_tid,
            saved_env: Vec::new(),
        })
    }

    pub fn fuzz_tid(&self) -> u32 {
        self.fuzz_tid
    }

    /// Run `target` on this (filtered) thread with `rng` answering every trapped syscall.
    ///
    /// Returns the RNG so the harness calls `coverage()`/`coverage_with_cost()`/`discard()` as
    /// usual, plus a report of what the sandbox did.
    pub fn run_case<Capture, R>(
        &mut self,
        rng: CaseRng<Capture>,
        spec: &Arc<Spec>,
        target: impl FnOnce() -> R,
    ) -> (CaseRng<Capture>, CaseReport, R)
    where
        Capture: CoverageCapture + Send + 'static,
        Capture::Token: Send,
    {
        let draw: Box<dyn Draw> = Box::new(RngDraw::new(rng));
        let session = self.start_case(draw, spec);
        // No trapped syscall may run between here and the unlock below.
        {
            let mut guard = self.shared.session.lock().expect("session poisoned");
            assert!(guard.is_none(), "sandbox case already active");
            *guard = Some(session);
        }
        let output = target();
        let session = self
            .shared
            .session
            .lock()
            .expect("session poisoned")
            .take()
            .expect("session vanished");
        let (rng, report) = self.finish_case(session);
        (rng, report, output)
    }

    fn start_case(&mut self, mut draw: Box<dyn Draw>, spec: &Arc<Spec>) -> Session {
        static NEXT_CASE: AtomicU64 = AtomicU64::new(0);
        let case_id = NEXT_CASE.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id() as libc::pid_t;
        let mut spec = Arc::clone(spec);
        let mut vfs = Vfs::new(crate::vfs::case_root(case_id));
        std::fs::create_dir_all(vfs.root()).expect("create per-case tmpfs dir");

        let applied = crate::env::apply(draw.as_mut(), &spec, &mut self.saved_env);
        let report = CaseReport {
            applied_env: applied,
            ..CaseReport::default()
        };
        if spec.virtual_environ {
            let blob = crate::env::environ_blob();
            let spec_mut = Arc::make_mut(&mut spec);
            for path in ["/proc/self/environ".to_string(), format!("/proc/{pid}/environ")] {
                let path = PathBuf::from(path);
                vfs.insert_fixed_file(&path, &blob)
                    .expect("materialize /proc/self/environ");
                spec_mut.nodes.push((
                    path,
                    crate::spec::NodeSpec::File {
                        content: crate::spec::Content::Fixed(Vec::new()),
                        may_fail: false,
                    },
                ));
            }
        }
        Session {
            draw,
            spec,
            vfs,
            mem: TargetMem::new(pid),
            identity: identity::IdentityState::new(pid as u32, self.fuzz_tid),
            entropy: entropy::EntropyState::default(),
            report,
        }
    }

    fn finish_case<Capture>(&mut self, mut session: Session) -> (CaseRng<Capture>, CaseReport)
    where
        Capture: CoverageCapture + Send + 'static,
        Capture::Token: Send,
    {
        crate::env::restore(&mut self.saved_env);
        let mut report = std::mem::take(&mut session.report);
        report.materialized_bytes = session.vfs.materialized_bytes;
        report.non_default_variants = session.vfs.non_default_variants + session.identity.non_default
            + session.entropy.non_default;
        report.touched = session.vfs.touched;
        report.draw_bytes = session.draw.consumed();
        report.trace_overflow = report.draw_bytes > session.spec.trace_budget;
        let mut files: Vec<(PathBuf, Vec<u8>)> = session
            .vfs
            .nodes()
            .iter()
            .filter_map(|(path, node)| match node {
                crate::vfs::Node::File { .. } => {
                    session.vfs.read_file(path).ok().map(|bytes| (path.clone(), bytes))
                }
                _ => None,
            })
            .collect();
        files.sort();
        report.files = files;
        session.vfs.cleanup();
        let mut draw = session.draw;
        let rng = draw
            .as_any_mut()
            .downcast_mut::<RngDraw<Capture>>()
            .expect("draw source has the harness capture type")
            .take();
        (rng, report)
    }
}

fn run_loop(shared: Arc<Shared>) {
    let listener = shared.listener;
    // SAFETY: plain syscall.
    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    assert!(epfd >= 0, "epoll_create1: {}", io::Error::last_os_error());
    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: listener as u64,
    };
    // SAFETY: valid fds and pointer.
    let rc = unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, listener, &mut ev) };
    assert!(rc == 0, "epoll_ctl: {}", io::Error::last_os_error());
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 8];
    loop {
        // SAFETY: valid fd and event buffer.
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), events.len() as i32, -1) };
        if n < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        for event in &events[..n as usize] {
            if event.u64 != listener as u64 {
                continue;
            }
            if event.events & (libc::EPOLLHUP as u32 | libc::EPOLLERR as u32) != 0
                && event.events & libc::EPOLLIN as u32 == 0
            {
                // Every filtered task exited.
                return;
            }
            match notif::recv(listener) {
                Ok(notification) => serve(&shared, notification),
                Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {
                    // The task was killed between poll and recv.
                }
                Err(err) if err.raw_os_error() == Some(libc::EINTR) => {}
                Err(err) => panic!("SECCOMP_IOCTL_NOTIF_RECV: {err}"),
            }
        }
    }
}

fn serve(shared: &Shared, notification: Notification) {
    let listener = shared.listener;
    let answer = {
        let mut guard = shared.session.lock().expect("session poisoned");
        match guard.as_mut() {
            None => Answer::Continue,
            Some(session) => {
                session.report.trapped += 1;
                *session.report.per_tid.entry(notification.tid).or_default() += 1;
                let answer = dispatch(session, listener, &notification);
                match answer {
                    Answer::Continue => session.report.continued += 1,
                    _ => session.report.answered += 1,
                }
                answer
            }
        }
    };
    let result = match answer {
        Answer::Continue => notif::send_continue(listener, notification.id),
        Answer::Ret(val) => notif::send(listener, notification.id, val, 0),
        Answer::Errno(errno) => notif::send(listener, notification.id, 0, errno),
        Answer::AddFd { fd, newfd, cloexec } => {
            let result = notif::addfd_send(listener, notification.id, fd, newfd, cloexec);
            // SAFETY: fd is owned by us.
            unsafe { libc::close(fd) };
            result.map(|_| ())
        }
    };
    if let Err(err) = result {
        if err.raw_os_error() == Some(libc::ENOENT) {
            // Target was interrupted by a signal and will re-issue the syscall: answers are
            // idempotent because draws are attached to materialized nodes.
            if let Some(session) = shared.session.lock().expect("session poisoned").as_mut() {
                session.report.send_retries += 1;
            }
        } else {
            panic!("SECCOMP_IOCTL_NOTIF_SEND: {err}");
        }
    }
}

fn dispatch(session: &mut Session, listener: i32, n: &Notification) -> Answer {
    let ctx = Ctx {
        listener,
        id: n.id,
        tid: n.tid,
    };
    match n.nr {
        libc::SYS_getpid | libc::SYS_gettid | libc::SYS_uname | libc::SYS_sysinfo => {
            identity::handle(session, &ctx, n)
        }
        libc::SYS_getrandom => entropy::getrandom(session, &ctx, n),
        libc::SYS_read
        | libc::SYS_pread64
        | libc::SYS_readv
        | libc::SYS_preadv
        | libc::SYS_preadv2 => entropy::read(session, &ctx, n),
        libc::SYS_open
        | libc::SYS_openat
        | libc::SYS_openat2
        | libc::SYS_stat
        | libc::SYS_lstat
        | libc::SYS_newfstatat
        | libc::SYS_statx
        | libc::SYS_readlink
        | libc::SYS_readlinkat
        | libc::SYS_access
        | libc::SYS_faccessat
        | libc::SYS_faccessat2 => fs::handle(session, &ctx, n),
        _ => Answer::Continue,
    }
}

/// Per-notification context handed to the handlers.
pub struct Ctx {
    pub listener: i32,
    pub id: u64,
    pub tid: u32,
}

impl Ctx {
    /// Write into the target only while it is still blocked in this very syscall.
    pub fn write(&self, mem: &TargetMem, addr: u64, bytes: &[u8]) -> io::Result<()> {
        if !notif::id_valid(self.listener, self.id) {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        mem.write(addr, bytes)
    }
}
