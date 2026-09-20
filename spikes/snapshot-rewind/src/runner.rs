//! Child-side machinery: the forkserver-shaped runner, paused holders, and
//! continuations resumed from a holder.
//!
//! Everything here runs in a forked child of the supervisor. State lives in a
//! process-global because the base crate's hooks are `Box<dyn FnMut + Send>`
//! and each runner is its own process anyway.

use crate::{
    fds::{self, FdInfo},
    policy::{Decision, DecisionInput, FdPolicy, SkipReason, SnapshotPolicy},
    proto::{Channel, Kind, Message, Verdict},
};
use iterator_fuzz::{
    CaseRng,
    coverage::CoverageCapture,
    snapshot_hooks::{Boundary, BoundaryKind, DetachedExecution},
};
use std::{
    io::Write,
    os::fd::{IntoRawFd, RawFd},
    panic::{self, AssertUnwindSafe},
    sync::Mutex,
    time::Instant,
};

/// Configuration inherited by a runner across `fork`.
#[derive(Debug, Clone)]
pub struct RunnerConfig {
    pub policy: SnapshotPolicy,
    pub expected_reuse: f64,
    pub free_slots: u32,
    /// Supervisor-owned fds the runner must close right after the fork.
    pub close_fds: Vec<RawFd>,
}

struct Ctx {
    channel: Channel,
    policy: SnapshotPolicy,
    expected_reuse: f64,
    free_slots: u32,
    origin: Instant,
    last_snapshot: Instant,
    holders_created: usize,
    finished: Option<DetachedExecution>,
    skips: Vec<(usize, SkipReason)>,
}

static CTX: Mutex<Option<Ctx>> = Mutex::new(None);

fn with_ctx<R>(f: impl FnOnce(&mut Ctx) -> R) -> R {
    let mut guard = CTX.lock().unwrap_or_else(|poison| poison.into_inner());
    f(guard.as_mut().expect("runner context missing"))
}

fn die(message: &str) -> ! {
    let _ = writeln!(std::io::stderr(), "snapshot-rewind runner: {message}");
    unsafe { libc::_exit(70) }
}

/// Fork the runner; the supervisor keeps `rng` and only the child consumes it.
///
/// Implemented as a raw `fork` around a closure so the parent's `CaseRng` is
/// untouched (it is a bitwise copy in the child, which is exactly what we want:
/// the child inherits the active coverage token and the byte cursor).
pub fn fork_runner<C: CoverageCapture + 'static>(
    rng: &mut CaseRng<C>,
    body: &mut dyn FnMut(&mut CaseRng<C>) -> Verdict,
    config: &RunnerConfig,
) -> std::io::Result<(i32, Channel)> {
    let (parent_end, child_end) = Channel::pair()?;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if pid == 0 {
        drop(parent_end);
        for fd in &config.close_fds {
            if *fd != child_end.raw() {
                unsafe {
                    libc::close(*fd);
                }
            }
        }
        unsafe {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        }
        let now = Instant::now();
        *CTX.lock().unwrap_or_else(|poison| poison.into_inner()) = Some(Ctx {
            channel: child_end,
            policy: config.policy.clone(),
            expected_reuse: config.expected_reuse,
            free_slots: config.free_slots,
            origin: now,
            last_snapshot: now,
            holders_created: 0,
            finished: None,
            skips: Vec::new(),
        });
        run_body_in_place(rng, body);
    }
    drop(child_end);
    Ok((pid, parent_end))
}

fn run_body_in_place<C: CoverageCapture + 'static>(
    rng: &mut CaseRng<C>,
    body: &mut dyn FnMut(&mut CaseRng<C>) -> Verdict,
) -> ! {
    rng.snapshot_install_hooks(
        Some(Box::new(on_boundary::<C>)),
        Some(Box::new(|execution: &DetachedExecution| {
            with_ctx(|ctx| ctx.finished = Some(execution.clone()));
        })),
    );

    let verdict = match panic::catch_unwind(AssertUnwindSafe(|| body(rng))) {
        Ok(verdict) => verdict,
        Err(_) => Verdict::Panicked,
    };
    rng.snapshot_clear_boundary_hook();
    let body_us = with_ctx(|ctx| ctx.origin.elapsed().as_micros() as u64);

    // Finish the capture in this process; the finish hook stashes the execution.
    let _ = rng.snapshot_finish(verdict != Verdict::Discard);

    let execution = with_ctx(|ctx| ctx.finished.take());
    let Some(execution) = execution else {
        die("execution finished without firing the finish hook");
    };
    let skips = with_ctx(|ctx| std::mem::take(&mut ctx.skips));
    if !skips.is_empty() {
        let _ = with_ctx(|ctx| {
            ctx.channel.send(
                &Message::Log(format!(
                    "skipped {} boundaries: {}",
                    skips.len(),
                    summarize_skips(&skips)
                )),
                None,
            )
        });
    }
    let result = with_ctx(|ctx| {
        ctx.channel.send(
            &Message::Finished {
                verdict,
                execution: Box::new(execution),
                body_us,
            },
            None,
        )
    });
    if let Err(error) = result {
        die(&format!("cannot report to supervisor: {error}"));
    }
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    unsafe { libc::_exit(0) }
}

fn summarize_skips(skips: &[(usize, SkipReason)]) -> String {
    let mut kind = 0;
    let mut cursor = 0;
    let mut budget = 0;
    let mut cliff = 0;
    let mut gap = 0;
    let mut cost = 0;
    let mut disabled = 0;
    for (_, reason) in skips {
        match reason {
            SkipReason::Kind => kind += 1,
            SkipReason::Cursor => cursor += 1,
            SkipReason::Budget => budget += 1,
            SkipReason::Cliff => cliff += 1,
            SkipReason::Gap => gap += 1,
            SkipReason::CostModel { .. } => cost += 1,
            SkipReason::Disabled => disabled += 1,
        }
    }
    format!(
        "kind={kind} cursor={cursor} budget={budget} cliff={cliff} gap={gap} cost_model={cost} disabled={disabled}"
    )
}

fn kind_of(kind: BoundaryKind) -> Kind {
    match kind {
        BoundaryKind::Item => Kind::Item,
        BoundaryKind::Variant => Kind::Variant,
        BoundaryKind::Hint => Kind::Hint,
    }
}

fn on_boundary<C: CoverageCapture>(rng: &mut CaseRng<C>, boundary: Boundary) {
    let now = Instant::now();
    let rss_kb = fds::rss_kb();
    let (decision, policy) = with_ctx(|ctx| {
        let input = DecisionInput {
            kind: kind_of(boundary.kind),
            cursor: boundary.cursor,
            since_origin: now.duration_since(ctx.origin),
            since_last_snapshot: now.duration_since(ctx.last_snapshot),
            holders_this_run: ctx.holders_created,
            free_slots: ctx.free_slots,
            expected_reuse: ctx.expected_reuse,
            rss_kb,
        };
        (ctx.policy.decide(&input), ctx.policy.clone())
    });
    match decision {
        Decision::Skip(reason) => {
            with_ctx(|ctx| {
                if ctx.skips.len() < 64 {
                    ctx.skips.push((boundary.cursor, reason));
                }
            });
        }
        Decision::Snapshot => {
            let prefix_cost_us = with_ctx(|ctx| now.duration_since(ctx.origin).as_micros() as u64);
            take_snapshot(rng, boundary, &policy, prefix_cost_us, rss_kb);
        }
    }
}

fn take_snapshot<C: CoverageCapture>(
    rng: &mut CaseRng<C>,
    boundary: Boundary,
    policy: &SnapshotPolicy,
    prefix_cost_us: u64,
    rss_kb: u64,
) {
    let threads = fds::thread_count();
    if threads > 1 {
        let _ = with_ctx(|ctx| {
            ctx.channel.send(
                &Message::Refused {
                    cursor: boundary.cursor,
                    reason: format!("process has {threads} threads; fork keeps only the caller"),
                },
                None,
            )
        });
        return;
    }
    let my_fd = with_ctx(|ctx| ctx.channel.raw());
    let infos = match fds::scan(&[my_fd, 0, 1, 2]) {
        Ok(infos) => infos,
        Err(error) => {
            let _ = with_ctx(|ctx| {
                ctx.channel.send(
                    &Message::Refused {
                        cursor: boundary.cursor,
                        reason: format!("cannot scan /proc/self/fd: {error}"),
                    },
                    None,
                )
            });
            return;
        }
    };
    let problems = fds::problems(&infos);
    if !problems.is_empty() {
        match policy.fds {
            FdPolicy::Refuse => {
                let _ = with_ctx(|ctx| {
                    ctx.channel.send(
                        &Message::Refused {
                            cursor: boundary.cursor,
                            reason: format!("shared fd state: {}", problems.join("; ")),
                        },
                        None,
                    )
                });
                return;
            }
            FdPolicy::Warn => {
                let _ = with_ctx(|ctx| {
                    ctx.channel.send(
                        &Message::Log(format!(
                            "snapshot at {} with shared fd state: {}",
                            boundary.cursor,
                            problems.join("; ")
                        )),
                        None,
                    )
                });
            }
            FdPolicy::Allow => {}
        }
    }

    let (holder_end, parent_end) = match Channel::pair() {
        Ok(pair) => pair,
        Err(error) => {
            let _ = with_ctx(|ctx| {
                ctx.channel.send(
                    &Message::Refused {
                        cursor: boundary.cursor,
                        reason: format!("socketpair: {error}"),
                    },
                    None,
                )
            });
            return;
        }
    };
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    let before = Instant::now();
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let error = std::io::Error::last_os_error();
        let _ = with_ctx(|ctx| {
            ctx.channel.send(
                &Message::Refused {
                    cursor: boundary.cursor,
                    reason: format!("fork: {error}"),
                },
                None,
            )
        });
        return;
    }
    if pid == 0 {
        drop(parent_end);
        holder_loop(rng, holder_end, infos);
        // Only a continuation returns here, with CTX re-pointed at its own channel.
        return;
    }
    let fork_us = before.elapsed().as_micros() as u64;
    drop(holder_end);
    let sent = with_ctx(|ctx| {
        ctx.holders_created += 1;
        ctx.free_slots = ctx.free_slots.saturating_sub(1);
        ctx.last_snapshot = Instant::now();
        ctx.channel.send(
            &Message::Holder {
                pid,
                trace: rng.snapshot_trace().to_vec(),
                kind: kind_of(boundary.kind),
                prefix_cost_us,
                fork_us,
                rss_kb,
            },
            Some(parent_end.raw()),
        )
    });
    drop(parent_end);
    if let Err(error) = sent {
        die(&format!("cannot hand holder to supervisor: {error}"));
    }
}

/// Runs in the holder. Waits for `Spawn`/`Reap`/`Exit`. Returns only inside a
/// freshly forked continuation, after re-pointing the runner context.
fn holder_loop<C: CoverageCapture>(rng: &mut CaseRng<C>, control: Channel, infos: Vec<FdInfo>) {
    // The holder must not keep the runner's supervisor channel open, otherwise
    // the supervisor never sees EOF when the runner exits.
    with_ctx(|ctx| {
        let old = std::mem::replace(&mut ctx.channel, Channel::dead());
        drop(old);
    });
    unsafe {
        // Do not die with the runner; die when the supervisor closes `control`.
        libc::prctl(libc::PR_SET_PDEATHSIG, 0);
    }
    loop {
        let message = match control.recv() {
            Ok(Some((message, fd))) => (message, fd),
            Ok(None) => unsafe { libc::_exit(0) },
            Err(_) => unsafe { libc::_exit(0) },
        };
        match message {
            (
                Message::Spawn {
                    stream,
                    expected_reuse,
                    free_slots,
                },
                Some(fd),
            ) => {
                let _ = std::io::stdout().flush();
                let pid = unsafe { libc::fork() };
                if pid < 0 {
                    let _ = control.send(
                        &Message::Log(format!("holder fork: {}", std::io::Error::last_os_error())),
                        None,
                    );
                    continue;
                }
                if pid == 0 {
                    // Continuation.
                    drop(control);
                    let channel = unsafe { Channel::from_raw_fd(fd.into_raw_fd()) };
                    let now = Instant::now();
                    with_ctx(|ctx| {
                        ctx.channel = channel;
                        ctx.expected_reuse = f64::from(expected_reuse);
                        ctx.free_slots = free_slots;
                        ctx.origin = now;
                        ctx.last_snapshot = now;
                        ctx.holders_created = 0;
                        ctx.finished = None;
                        ctx.skips.clear();
                    });
                    let errors = fds::restore_offsets(&infos);
                    if !errors.is_empty() {
                        let _ = with_ctx(|ctx| {
                            ctx.channel
                                .send(&Message::Log(errors.join("; ")), None)
                        });
                    }
                    if let Err(error) = rng.snapshot_install_stream(stream) {
                        die(&format!("cannot resume from holder: {error}"));
                    }
                    return;
                }
                drop(fd);
                if control.send(&Message::Spawned { pid }, None).is_err() {
                    unsafe { libc::_exit(0) }
                }
            }
            (Message::Spawn { .. }, None) => {
                let _ = control.send(&Message::Log("Spawn without fd".to_string()), None);
            }
            (Message::Reap { pid }, _) => {
                let mut status = 0;
                let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
                let status = if rc == pid { status } else { -1 };
                if control.send(&Message::Reaped { pid, status }, None).is_err() {
                    unsafe { libc::_exit(0) }
                }
            }
            (Message::Exit, _) => unsafe { libc::_exit(0) },
            (other, _) => {
                let _ = control.send(
                    &Message::Log(format!("holder ignoring {other:?}")),
                    None,
                );
            }
        }
    }
}
