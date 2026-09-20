# Dowsing as a sandboxed system-fuzzing environment (Linux, one machine)

Synthesis of the seven spike branches (`devin/spike/{coverage-bridge, net-intercept,
thread-scheduler, snapshot-rewind, virtual-time, fs-env-intercept, shrink-quality}`) into one
architecture. Every number in this document was either re-measured on this machine while writing
it (kernel `6.8.0-1061-aws`, 8 vCPU, Rust 1.98.1, `ptrace_scope=1`) or is quoted from a spike's
`README.md`/`RESULTS.md` and marked as such. §12 lists what was *not* reproduced.

Base branch: `devin/1789863721-linux-rtld-default` (`84b80ef`, root `cargo test` 54/54, clippy 2
pre-existing warnings). Every spike is a standalone crate under `spikes/<name>/` depending on the
root crate by path; three spikes also patch the root crate (`coverage-bridge`, `shrink-quality`,
`snapshot-rewind`) and those patches are the first things to reconcile (§10 step 0).

---

## 0. TL;DR — the decisions

| Question | Decision | Why (evidence) |
|---|---|---|
| Where does target code run? | **Always in a forked child** of a forkserver, never in the fuzzer process. | fs-env prototype (in-process, thread-scoped filter) dies with the target on a crash and leaks `setenv` across cases; every other spike already forks. Fork+exit ≈ 0.2–0.35 ms at ≤10 MiB RSS (measured 199 µs net-intercept, 116/341 µs coverage-bridge at 1/10 MiB). |
| Data-plane syscalls (socket ops, `openat`/`stat*` on virtual paths, `getrandom`, `/dev/urandom`, `uname`/`get*id`) | **`SECCOMP_RET_USER_NOTIF`** | 2.4 µs/trap pinned vs 10–17 µs for a ptrace stop (both re-measured today); `SECCOMP_IOCTL_NOTIF_ADDFD` is the only way to inject a real fd; the kernel keeps doing the real I/O on socketpair/tmpfs fds. |
| Control-plane syscalls (anything that can block or change the thread set: `futex`, `poll`/`epoll_wait`/`select`, `nanosleep`, `clock_*`, `timerfd_*`, `clone*`, `exit*`, `execve`) | **`SECCOMP_RET_TRACE` + ptrace** | Needs per-thread stop/resume, register rewriting (skip syscall, set return value), `PTRACE_EVENT_CLONE/EXEC/EXIT`, and `PTRACE_INTERRUPT` for preemption — none of which unotify offers. thread-scheduler and virtual-time both settled here independently. |
| One syscall in two lanes? | **Never.** One BPF program generated from one table; each syscall number has exactly one action. | Stacked filters resolve by action precedence: `USER_NOTIF (0x7fc0xxxx)` beats `TRACE (0x7ff0xxxx)` (seccomp(2)), so the ptrace lane would silently never see `poll`/`futex`/`getrandom` if the net/fs filters were simply layered on the sched/time filter. Today those three spikes *do* overlap on `poll*`, `epoll_*`, `select*`, `getrandom` (§4.2). |
| `LD_PRELOAD` | **Not a mechanism; at most a later fast path.** | Misses static/musl binaries, raw syscalls, vDSO, glibc-internal aliases; cannot stop threads or see kernel-side blocking. No spike needed it. |
| Deterministic multithreading | **One runnable target thread at a time; scheduling decisions are `variant`s.** | 20/20 seeds found all three concurrency bugs; 100/100 replay hashes identical (re-run today: `0x6c0e5348425d4104` × 100). Cost ≈ 11 µs/stop, 1.7–1.9× native on the demos. |
| Time | **One virtual clock advanced only at quiescence; vDSO hidden at `exec` so clock reads become trapped syscalls.** | 120 s backoff bug found in 2.9 ms wall (re-run today); 100/100 deterministic single-threaded, **0/100 multi-threaded** without the scheduler — so time depends on sched (§10 order). |
| Snapshots | **Optional fork/COW prefix cache, span-aligned, used by `cautious()`; not a correctness mechanism.** | Re-run today: `cautious` 198/200 candidates served from holders (159 ms vs 1108 ms, 7×); `curious` 0/400 served (mutation changes the prefix). Fork restores memory + fd table, *not* socket/pipe contents, other threads, or the virtual clock. |
| Where the random stream lives | **One `CaseRng` stream, one cursor in shared memory, exactly one drawer at a time.** | Harness draws (in the child) and environment draws (in the supervisor) interleave deterministically because the child is stopped whenever the supervisor draws. Keeps `Case = seed + prefix + spans` and all of `cautious()` unchanged. |
| Shrinking | **Merge `shrink-quality` as-is; every environment decision is a `range`/`variant`; every harness passes a domain cost.** | Re-run today: unstructured `buggy_stack` seed 7 minimises to 52 ops with `coverage()` and 5 ops with `coverage_with_cost(ops.len())`; structured sampling 10/10 at 5 ops. |

---

## 1. Inventory: what each spike built and what I re-ran

| Spike | Mechanism | Re-run today (this machine) | Verdict |
|---|---|---|---|
| coverage-bridge | forkserver + shm (`fill_budget`/`absorb_trace` root hooks, child reuses `SancovCoverage` decode) | `buggy_stack_bridge --mode fork --seed 1`: bug at case 2, minimised to 5 ops in 4096 cases (2747 exec/s); bench 858 exec/s (cmp) / 1170 (no cmp) vs **406 exec/s in-process with cmp**; abort demo: crash detected, but crash cases minimise to "0 ops, 4096 bytes" because the trace is not exported on crash | Keep the shm layout, budget mirror, `_exit(128+sig)` crash export. Must add incremental span publication (§5.5). |
| net-intercept | unotify; fake fds ≥1000; AF_UNIX socketpair data plane; `poll`/`epoll` gated; DNS synthesised; `io_uring_setup→ENOSYS` | `std_client --no-coverage --seed 1`: bug in 18 cases (1885 cases/s), shrunk to 3 decisions/26 bytes; `tokio_client` same bug at 1392 cases/s; 23 268 syscalls intercepted, 16 867 continued | Keep. Readiness gating moves to the ptrace lane (§4.2). |
| thread-scheduler | ptrace + `RET_TRACE`; `sched-target-rt` linked into target (`trace_pc_guard` edge budget, yield marker = `getppid`); futex emulation; deadlock detection | `sched_fuzz fuzz sched_lost_update 0`: failure after 45 cases (69 ms), minimised to 3 non-zero variants; `sched_deadlock`: deadlock after 43 cases, 2 non-zero variants; 100/100 identical replay hashes | Keep as the scheduler core. |
| virtual-time | ptrace + `RET_TRACE`; hide `AT_SYSINFO_EHDR`; park waits; advance at quiescence; `announce` syscall (0x1337) for sancov counter range | `vt_run probe_target`: 10 077 stops, 10 030 clock reads, 23.5 s virtual in 98.7 ms wall; `backoff_sandbox`: bug at run 2 in 2.9 ms, minimised, replay 100/100; tokio `--multi`: **0/100** identical | Keep clock/park/quiescence; multi-thread determinism is the scheduler's job. Needs the shared-page clock fast path (designed, not built). |
| fs-env-intercept | unotify (thread-scoped, in-process target); tmpfs materialisation; `ADDFD`; entropy/identity/env | `sandboxed_config`: bug after 5078 cases (4770 cases/s, cmp-guided), replay 3/3, minimised to `mode=strict\n` + `APP_MODE=strict` + entropy `[3,0,…]`; `latency`: getpid 0.08→2.43 µs, passthrough open +3.53 µs, empty case 96 727/s, demo target 17 488/s | Keep VFS/entropy/identity/env models; drop in-process mode; `Isolation::Fork` was designed, not built. |
| snapshot-rewind | fork-based holder tree, `SOCK_SEQPACKET` protocol, root `snapshot_hooks` (boundary/finish hooks, `DetachedExecution`) | `demo --rss-mb 100 --n 32`: 14× (3.7 ms vs 53.8 ms/candidate); `latency --rss-mb 10`: continuation p50 0.43 ms; `curious --cases 400`: 32 holders, **0 continuations**; `cautious`: 198/200 continuations, 7× | Keep the holder protocol as an optional `cautious()`/replay accelerator. `tests/` are stubs (`fn main() {}`); no README/RESULTS was written. |
| shrink-quality | root reducer changes (deletion-first order, `LengthProbe`, draw-granular `DeleteRange`, structural-only restart) + structured `buggy_stack` | `run_matrix.sh` seeds 1,7: unstructured/no-cost → 5, **52**; unstructured/cost → 5, 5 (matches RESULTS.md exactly) | Merge first; independent of everything else. |

All seven spike crates build with `cargo build --release --all-targets` (`/home/ubuntu/build-all.log`).

---

## 2. Process topology

```
fuzzer process P  (user's harness: `for rng in curious()`; owns State, corpus, reducer,
│                  Supervisor; one supervisor thread per CPU, pinned)
│
├─ forkserver F  (execve'd once per target binary or forked once from P in in-process mode;
│   │              seccomp filter installed; PTRACE_TRACEME/SEIZE'd by P's supervisor thread;
│   │              waits on a control pipe; `PR_SET_PDEATHSIG`)
│   │
│   └─ per case: fork → target T  (one process, N threads; runs one case; _exit)
│         T's threads: T0 T1 T2 …   ← exactly one is runnable at any time (§3.4)
│
├─ optional holders H_k  (paused forks of a runner at stream offset k; §3.6)
│
└─ shared memory (memfd, one per supervisor thread):
     [header | budget bytes | shared cursor | span ring | coverage counters | verdict]
```

Two ways a user can put a target under the sandbox — both go through the same supervisor:

* **Mode A — external binary.** The target is any Linux executable (`cargo build` output, a Go
  server, a C daemon). The harness body runs in P, draws every decision from `CaseRng`, and talks
  to the target only through the sandboxed environment (virtual files, fake sockets, argv/env,
  stdin, time, scheduler). Coverage comes from the target's sancov counters if it has them
  (announced via a reserved syscall, read out of its memory at exit), otherwise `NoCoverage`.
  This is what net-intercept, thread-scheduler and virtual-time did.
* **Mode B — in-process harness.** The harness body (Rust code that calls the target library, as
  in `buggy_stack`) runs *inside T* against a mirror of the byte budget (coverage-bridge). P is a
  thin supervisor; the body's `CaseRng` draws happen in T through the shared cursor. This is how
  today's `curious()` users get the sandbox without rewriting their harness.

Both modes share: forkserver, seccomp program, supervisor loop, virtual clock, scheduler,
per-thread state, shm layout, crash/timeout/deadlock verdicts, coverage import.

---

## 3. The single supervisor

### 3.1 One event loop

The supervisor thread (one per CPU; ptrace requires all ptrace calls to come from the tracer
thread, so the ptrace lane and the unotify lane must be served by the *same* thread) runs:

```rust
loop {
    let n = epoll_wait(epfd, &mut events, timeout = if runnable.is_empty() && !parked.is_empty() { 0 } else { -1 });
    for ev in events {
        match registry[ev.data] {
            Source::Notif(listener)   => drain_notifications(listener),   // unotify lane, level-triggered
            Source::SigChld(signalfd) => drain_waitid(),                   // ptrace lane: waitid(P_ALL, __WALL|WNOHANG) until ECHILD/none
            Source::PidFd(pid)        => on_process_gone(pid),
            Source::Control(pipe)     => on_forkserver_message(),
        }
    }
    if runnable.is_empty() {
        if let Some(t) = clock.next_deadline_owner(&parked) { clock.advance_to(t.deadline); wake(t); }   // quiescence rule
        else if parked.is_empty() { /* case finished or crashed */ }
        else { verdict = Deadlock(parked.tids()) }
    }
    if let Some(t) = scheduler.pick(&runnable, &mut rng) { resume(t); }
}
```

Both lanes reduce to the same `Event { tid, kind }` and feed one `dispatch(tid, syscall)`:

```rust
enum Event {
    Notif { tid: Tid, id: u64, nr: i64, args: [u64; 6] },          // unotify: answer or hold
    SyscallStop { tid: Tid, regs: Regs },                          // PTRACE_EVENT_SECCOMP (RET_TRACE)
    Marker { tid: Tid },                                           // yield marker (getppid) from target-rt
    Clone { parent: Tid, child: Tid }, Exec { tid: Tid }, Exit { tid: Tid, status: i32 },
    Signal { tid: Tid, sig: i32 },
}
```

### 3.2 One syscall table, two lanes

The BPF program is generated from a single table; each syscall appears once. With stacked
filters the kernel applies the highest-precedence action, in the order `KILL_PROCESS, KILL_THREAD,
TRAP, ERRNO, USER_NOTIF (0x7fc00000), TRACE (0x7ff00000), LOG, ALLOW` (seccomp(2),
`linux/seccomp.h`) — so layering the spike filters would route the whole wait family to unotify
and starve the scheduler. Generating one program avoids the question.

| Family | Syscalls | Lane | Handler owns |
|---|---|---|---|
| socket lifecycle | `socket`, and on fake fds: `connect bind listen accept4 getsockopt setsockopt getsockname getpeername shutdown close dup* fcntl ioctl` | unotify | `net::Model`; answers or `ADDFD`s a socketpair end |
| socket data | on fake fds: `read readv recvfrom recvmsg recvmmsg write writev sendto sendmsg sendmmsg` | unotify (immediate) or `CONTINUE` into the kernel-backed socketpair | `net::Model` decides `variant{Data, WouldBlock, Eof, Reset}`; `WouldBlock` on a blocking fd ⇒ **hold** the notification and park the thread (§3.4) |
| virtual filesystem | `openat openat2 newfstatat statx readlinkat getdents64 access faccessat2 chdir` on paths under a virtual root | unotify | `fs::Vfs`; materialises on tmpfs lazily, `ADDFD`s the real fd; everything else `CONTINUE` |
| entropy & identity | `getrandom`, `read` on the urandom fd window, `getpid getppid getuid geteuid getgid gettid uname sysinfo` | unotify | `entropy`, `identity`; writes answers via `/proc/<pid>/mem` |
| readiness waits | `poll ppoll select pselect6 epoll_wait epoll_pwait epoll_pwait2` | **ptrace** | `waits`: evaluates readiness of real fds via a non-blocking probe (`timeout=0` reissue), fake fds via `net::Model`, timeouts via the virtual clock; parks or returns |
| sleeping / futex | `nanosleep clock_nanosleep futex futex_waitv` | ptrace | `sched` + `clock`; futex wait/wake emulated in supervisor state so `FUTEX_WAIT` with timeout is a virtual deadline |
| clock | `clock_gettime clock_getres gettimeofday time` (real syscalls because `AT_SYSINFO_EHDR` is removed from auxv at exec) | ptrace | `clock`; skip syscall, write result |
| timers | `timerfd_create timerfd_settime timerfd_gettime setitimer timer_*` | ptrace | `clock` (timerfd readiness is virtual) |
| thread set | `clone clone3 execve execveat exit exit_group set_tid_address set_robust_list rseq` | ptrace (events, not RET_TRACE) | `sched` |
| yield marker | `getppid` from `target-rt` (thread-scheduler), `0x1337` announce (virtual-time) — unify to two reserved numbers | ptrace | `sched` (preemption point), `coverage` (counter range) |
| rejected | `io_uring_setup io_uring_enter io_uring_register` → `ERRNO(ENOSYS)`; `ptrace` → `EPERM`; `seccomp`/`prctl(PR_SET_SECCOMP)` → `EPERM`; `unshare/setns` → `EPERM` | seccomp `ERRNO` | — |
| everything else | `mmap brk read/write on real fds …` | `ALLOW` | — |

Rationale for the split, stated once: **a syscall goes to unotify iff the supervisor can answer it
immediately without changing which thread runs next.** Anything that can block, sleep, wait on
time, or create/destroy threads is a scheduling event and belongs to the lane that can also stop a
thread at an arbitrary instruction. One exception is explicit: a data-plane call that *would*
block (blocking `recv` with `WouldBlock` chosen) is handled by *holding* the notification, which
turns a unotify event into a parked thread without a second trap.

### 3.3 Per-thread state machine

```rust
struct Thread {
    tid: Tid,
    state: ThreadState,
    stop: Option<StopKind>,          // where it is stopped (SyscallEntry{regs} | Marker | Signal | CloneEvent | ...)
    held: Option<HeldNotif>,         // an unanswered unotify id, if parked via the unotify lane
    edges_budget: u32,               // preemption budget written to shm before resume (target-rt decrements)
}
enum ThreadState {
    Runnable,                        // stopped by us, may be resumed
    Running,                         // exactly one thread may be here
    Parked(WakeCondition),           // FutexWait{addr}, Sleep{deadline}, Poll{fds, deadline}, Notif(HeldNotif), JoinExit(tid)
    Exited,
}
```

Invariants (each traces to a spike observation or documented limitation):

1. At most one thread is `Running` (thread-scheduler). Data-plane answers (unotify) never change
   this — they respond and leave the thread `Running`.
2. A thread with `held.is_some()` is never sent `PTRACE_INTERRUPT` or a signal: a signal cancels
   the pending notification (`SECCOMP_IOCTL_NOTIF_SEND` → `ENOENT`, the syscall restarts and
   re-notifies). Resume for a held thread is *respond*, not `PTRACE_CONT`.
3. The virtual clock advances only when `runnable.is_empty()` (virtual-time's quiescence rule). It
   advances to the earliest parked deadline; if none, the case is a `Deadlock`.
4. Every `Parked` thread has a wake condition owned by supervisor state, never by the kernel:
   `futex` waits are emulated (the real `futex` syscall is skipped), sleeps are skipped, polls are
   evaluated by non-blocking probes. If a thread could block inside the kernel invisibly, rule 3
   would advance time while it is still "running" — virtual-time §limitations documented exactly
   this hole for unsupervised blocking syscalls.
5. Threads are identified by kernel TID in both lanes (`seccomp_notif.pid` is a TID; ptrace stops
   are per TID), so one `HashMap<Tid, Thread>` serves both.

### 3.4 One scheduler

The scheduler is the only component that resumes threads. It runs when no thread is `Running`:

```rust
fn pick(&mut self, runnable: &[Tid], rng: &mut dyn Draw) -> Option<Tid> {
    if runnable.is_empty() { return None; }
    let item = self.decisions.next()?;                        // decisions: range(0..MAX_DECISIONS) opened at case start
    let pick   = item.variant(runnable.len());                // 0 = lowest TID = FIFO default → shrinks to "no reordering"
    let budget = BUDGET_TABLE[item.variant(BUDGET_TABLE.len())]; // 0 = run until next syscall/marker
    Some(runnable[pick]).inspect(|t| shm.set_budget(*t, budget))
}
```

Preemption points = every ptrace-lane syscall + every yield marker emitted by `target-rt` when the
edge budget hits zero (`__sanitizer_cov_trace_pc_guard` decrements it). Uninstrumented code
(libc, other languages) is preempted only at syscalls; that is a fidelity limit, not a soundness
one (§12).

Virtual-time's realtime/quantum decisions fold into the same `decisions` sequence: a time jump is
just another scheduler decision `variant{Natural, +1ms, +1s, +1min…}` taken at quiescence.

### 3.5 One stream, one cursor

`Case` stays `seed + prefix + spans`. The supervisor allocates a byte budget (`fill_budget`, from
coverage-bridge) into shm and a shared `cursor: AtomicU32`. Drawers:

* the child's `CaseRng<NoCoverage>` mirror (Mode B): `next_byte` = `cursor.fetch_add(n)` then read
  `budget[i..i+n]`; spans are pushed to a ring in shm as they close (async-signal-safe `memcpy`);
* the supervisor's environment models (`net`, `fs`, `sched`, `clock`, `entropy`): same cursor, same
  budget, spans pushed to the supervisor's local trace.

Because a supervisor draw happens only while the child is stopped (unotify held or ptrace stop),
and only one child thread runs at a time, the interleaving is a total order and identical on
replay. At case end (or crash: header + ring are already in shm) `absorb_trace` merges the two
span lists by stream offset into the ordinary `CaseRng` trace and finishes the capture. Budget
exhaustion retries the same candidate with a larger budget (coverage-bridge), never a failure.

This is what makes every environment decision a first-class shrinkable span with zero changes to
`shrink.rs`.

### 3.6 Where snapshots plug into the search loop

A holder is a paused fork of a runner at a `range`-item or `variant` boundary at stream offset `k`
(snapshot-rewind §8). In the unified design the boundary hook fires in *both* drawers: the
child's mirror can fork itself (Mode B, single-threaded at that instant — checked via
`/proc/self/status Threads:`), and the supervisor can request a fork of a single-threaded T via
the forkserver (Mode A). The supervisor snapshots its own per-case state alongside
(`Clone` of `Session { clock, threads, vfs materialised set, net model, cursor }`, per the fs-env
DESIGN §5), so a continuation resumes both halves.

Policy, from the measurements: a holder pays when `prefix_cost > fork_rt(RSS)`, i.e. > ~0.35 ms
at 10 MiB, > ~1.1 ms at 100 MiB (snapshot-rewind §1.1; today's continuation p50 0.43 ms at 10 MiB
including reap). `curious()` almost never matches a holder (0/400 today) because mutations hit
early bytes; `cautious()` matches nearly always (198/200) because reducers edit within or after a
span. Therefore: snapshots are **on by default only in `cautious()` and replay**, and only for
targets whose cost model says the prefix is expensive.

Not restored by fork — and therefore refused by the holder policy unless the sandbox owns the
object: sockets/pipes/epoll contents (fine under the sandbox: fake sockets *are* supervisor
state), file offsets on shared regular files (re-`lseek` from recorded `fdinfo`), other threads
(phase-2 rr-style re-clone; not planned), pending signals/timers.

---

## 4. Mechanism decisions and where the spikes conflict

### 4.1 Compatibility matrix

| Pair | Compatible? | Resolution |
|---|---|---|
| unotify + ptrace on the same process | Yes (net-intercept and fs-env verified: notifications from ptraced children work; ptrace_scope=1 parent→child) | One thread serves both; disjoint syscall sets (§3.2). |
| unotify + ptrace on the same **thread** at the same time | Only if ptrace never signals a thread that holds a notification | Invariant 2 in §3.3. |
| ptrace `PTRACE_INTERRUPT` preemption + futex emulation | Yes; scheduler already emulates `FUTEX_WAIT/WAKE/(BITSET/REQUEUE not done)` | Extend the emulated op set; `futex_waitv` and `FUTEX_LOCK_PI` are open (§12). |
| fork/COW snapshots + fake sockets | Yes, *because* socket state is supervisor state; would be incompatible with real sockets | Snapshot `Session` with the process. |
| fork/COW snapshots + multithreaded T | No (fork copies one thread) | Refuse; phase-2 rr-style re-clone only if a real target needs it. |
| virtual time + free-running threads | Wrong answers (0/100 replay identical) | Time requires the scheduler; ship them together (§10). |
| `LD_PRELOAD` + anything | Compatible but redundant | Not used; optional in-process clock read fast path later (§4.4). |
| sancov inline-8bit counters + parallel supervisors | Not safe in one process (process-global counters) — but every T is its own process | Parallelism = one supervisor thread + one forkserver per CPU; counters are per-T memory read at exit; the fuzzer-side `SancovCoverage` is unused. `trace-pc-guard` is only needed for the edge budget (`target-rt`), not for parallelism. |
| tmpfs materialisation + continuations | Shared directory between siblings | Per-holder subdirectory; `copy_file_range` on tmpfs (fs-env R8). |

### 4.2 Overlaps that exist today and how they are settled

* `poll/ppoll/select/pselect6/epoll_wait/epoll_pwait/epoll_pwait2`: trapped by net-intercept
  (unotify, to gate fake fds), thread-scheduler (TRACE, scheduling point) and virtual-time
  (TRACE, timeout → deadline). **→ ptrace lane.** The `waits` handler asks `net::Model` about fake
  fds and probes real fds with a `timeout=0` reissue; the union decides `Return(n)` vs
  `Park{deadline}`. net-intercept's `/proc/<pid>/fdinfo/<epfd>` scan (needed because mio dups the
  epoll fd) stays as the way to learn which fake fds an epoll set contains.
* `getrandom`: unotify in fs-env (answered from case bytes, `variant`-recorded), TRACE in
  thread-scheduler and virtual-time (same answer). **→ unotify** (immediate, cheaper); the ptrace
  spikes drop it from their tables.
* `futex`: only thread-scheduler emulates it; virtual-time traps it only for the timeout.
  **→ ptrace lane, owned by `sched`, deadline supplied by `clock`.**
* `nanosleep/clock_nanosleep`: both ptrace spikes park; identical semantics. **→ `clock`.**
* yield/announce markers: `getppid` (sched) vs `0x1337` (time). **→ two reserved numbers in
  `target-rt`, both in the ptrace lane**; `getppid` reclaimed for `identity`.
* `close/dup*/fcntl` on fake fds (net) vs everything else `ALLOW`: keep the `NotifyIfFakeFd(arg0
  ≥ FAKE_BASE)` BPF guard so real fds pay nothing. SCM_RIGHTS escape of a fake fd is unhandled
  (§12).

### 4.3 Why not ptrace for everything

ptrace stop ≈ 10–17 µs vs 2.4 µs (pinned) / 7.5–9 µs (unpinned) for a notification, both
re-measured; and no `ADDFD` — you would have to emulate every `read` on a virtual file instead of
handing the kernel a real tmpfs fd (fs-env: virtual file open+read+close 8.55 µs total, vs one
trap per `read` under ptrace). fs-env's `100 real opens` case (passthrough tax 3.5 µs/open) would
be ~4× worse under ptrace.

### 4.4 Why not unotify for everything

It cannot stop a thread that is not in a syscall, cannot observe `clone`/`exec`/`exit` as events,
cannot modify registers to *skip* a syscall and substitute a result while the kernel also
performs a different action, and holding a notification is cancelled by any signal. The
thread-scheduler DESIGN reached the same conclusion; net-intercept kept ptrace "for narrow
register/memory needs". Both are right; the split in §3.2 is the boundary.

### 4.5 vDSO and the clock cost

Hiding `AT_SYSINFO_EHDR` (rewrite auxv at `PTRACE_EVENT_EXEC`) makes every `clock_gettime` a real
syscall → TRACE stop → ~11 µs (probe: 10 030 clock reads in 98.7 ms). Native vDSO reads are ~20
ns. A hot loop on `Instant::now()` is 500× slower. The designed-but-unbuilt fast path: the
supervisor `mmap`s a shared page into T at a fixed address containing `(virtual_ns, realtime_offset,
generation)` and `target-rt` provides `clock_gettime` via that page (for Rust std targets this is
a symbol override in `target-rt`; for glibc targets an `LD_PRELOAD`-style shim is the only
non-ptrace option, and it is the one place `LD_PRELOAD` earns a role). Decision for Evan (§11 D4).

### 4.6 CPU pinning

Same-CPU supervisor/target pairs: 2.4 µs vs 8–9 µs per notification, 17 123 vs 7 388 cases/s on
the fs-env demo (README), 17 488 cases/s re-measured today. Design consequence: parallelism is
"one supervisor thread + one forkserver + one T pinned per CPU", not a shared supervisor. This
also sidesteps `ParallelCoverageCapture` and inline-counter globality.

---

## 5. Plugging into `curious()` / `cautious()` / `CaseRng`

### 5.1 What stays the same

`curious()`, `cautious()`, `Case`, `Case::replay()`, `coverage()`, `coverage_with_cost()`,
`discard()`, `range()`, `variant()`, the reducer passes, `CautiousOptions`. The sandbox is a
`CoverageCapture` plus an iterator adaptor; no new search loop.

### 5.2 Root-crate changes required (all small, all already prototyped)

| Hook | Prototyped in | Purpose |
|---|---|---|
| `CaseRng::fill_budget(&mut self, out: &mut [u8])` / `absorb_trace(&mut self, RawCase)` | coverage-bridge | Export a byte budget, import consumed bytes + spans from the child |
| `pub mod raw { RawCase, DrawSpan, SequenceSpan, SemanticSpan }` | coverage-bridge | Child-side span types |
| `sancov::decode_counters(&[u8]) -> ExecutionFeedback`, `counter_ranges()` | coverage-bridge | Decode a foreign process's counter bytes |
| boundary hook (`fire_boundary(BoundaryKind)`), `DetachedExecution`, `snapshot_install_stream`, `snapshot_record/abandon` | snapshot-rewind | Span-boundary callback for holders; ship trace+feedback out of the executing process |
| `LengthProbe` pass, deletion-first order, draw-granular `DeleteRange`, structural-only restart | shrink-quality | Reducer quality (RESULTS.md ablation) |

`coverage-bridge`'s `fill_budget/absorb_trace` and `snapshot-rewind`'s `install_stream /
DetachedExecution` solve the same problem (a `CaseRng` whose bytes are consumed elsewhere) with
two APIs. **Unify into one `#[doc(hidden)] pub mod stream`**: `StreamSpec { seed, prefix,
zero_tail, cursor }`, `DetachedExecution { trace, spans, feedback, cost, verdict }`,
`CaseRng::detach(&self) -> StreamSpec`, `CaseRng::attach(&mut self, DetachedExecution)`. §10 step 0.

### 5.3 What is a `range`, what is a `variant`, what is a payload draw

Rule (fs-env, snapshot-rewind §8.6, thread-scheduler all converge on it): **every decision that
changes what state is built or which branch the environment takes is a span; only bytes that
are data are raw draws.** The default of every `variant` (index 0) must be the *least surprising*
behaviour so shrinking towards zero means "the environment did nothing unusual".

| Decision | Span | Default (index 0) | Shrinks via |
|---|---|---|---|
| number of network events / files / dir entries / config lines / scheduler decisions / time jumps | `range(0..N)` | empty | `SequenceDelete`, `SemanticLength`, `LengthProbe` |
| peer action per event | `variant{Accept, Refuse, Reset, Timeout, Eof}` | `Accept` | `SemanticSimplify` |
| readiness of a fake fd at a poll | `variant{Ready, WouldBlock}` | `Ready` | `SemanticSimplify` |
| short read/write length | `variant(len+1)` mapped as `0 ⇒ full` | full | `SemanticSimplify` |
| syscall fault injection (`ENOMEM`, `EINTR`, `EIO`) | `variant{Ok, …}` | `Ok` | `SemanticSimplify` |
| scheduler pick / budget | `item.variant(runnable.len())`, `item.variant(BUDGET_TABLE.len())` | FIFO, run-to-syscall | `SemanticSimplify`, `SemanticDelete` |
| virtual-time jump at quiescence | `variant{Natural, +1ms, +100ms, +1s, +1min, +1h}` | `Natural` (to the next deadline) | `SemanticSimplify` |
| clock quantum / realtime mode | one `variant` each at case start | 1 µs / fixed epoch | `SemanticSimplify` |
| identity (`uid`, hostname, pid) | `variant{Default, Root, Random}` | `Default` | `SemanticSimplify` |
| env var present / value | `variant{Unset, Set}` + payload | `Unset` | `SemanticSimplify`, `BlockZero` |
| file/socket payload bytes, entropy bytes, config values | raw draws inside the item | zeros | `BlockZero`, `ByteLower`, `DictionaryRepair` |

### 5.4 Domain cost — mandatory, not optional

RESULTS.md shows why: with `coverage()` the score is `(features, hit_weight, bytes, …)`, and a
52-op case that fails *early* has fewer features than any 44-op case that runs to the end, so byte
deletion cannot escape it (seed 7: 52 ops; with `coverage_with_cost(ops.len())`: 5 ops, re-run
today). Environment fuzzing produces exactly such early-failure plateaus (a `Reset` on event 1
executes less code than `Accept…Accept, Reset`). Every sandbox harness therefore finishes with a
cost, and the sandbox computes it:

```rust
pub struct SandboxCost {        // summed into one u64 by `SandboxCost::total()`; weights are per-model defaults
    pub events: u32,            // network events, files, lines, scheduler decisions actually consumed
    pub nondefault_variants: u32,   // every variant != 0 (fs-env `CaseCost`, thread-scheduler "non-zero variant spans")
    pub materialized_bytes: u32,    // file + payload bytes
    pub nonzero_entropy: u32,       // fs-env: without this cautious() never zeroes served randomness
    pub virtual_elapsed_ms: u32,    // virtual-time: `jumps*1000 + non_natural*10_000 + secs`
}
```

`rng.coverage_with_cost(ctx.cost().total() + harness_cost)` is what the harness examples in §8 do.

### 5.5 Crashes, timeouts, deadlocks must shrink too

coverage-bridge's abort demo re-run today: the crash is detected, but minimisation ends at "0 ops,
4096 bytes" because the child never exported its spans. Fix in the unified shm layout: spans are
published to the ring **as they close** (one `memcpy` per span, no syscalls), and the cursor is in
shm, so on `SIGSEGV`/`SIGABRT`/`SIGKILL`(timeout) the supervisor already has the trace up to the
last completed draw. Verdicts:

```rust
pub enum Verdict {
    Passed, Failed(String), Panicked(Option<String>),
    Crashed { signal: i32, tid: Tid },
    TimedOut { wall: Duration, virtual_elapsed: Duration },
    Deadlock { parked: Vec<Tid> },          // thread-scheduler: detected, never a hang
    BudgetExhausted,                        // internal: retried with 2× budget, never surfaced as failure
    SupervisorError(String),                // internal: discard()ed
}
```

`discard()` is called for `SupervisorError` and for variants whose replay changes verdict class
(replay check runs `Case::replay()` in a fresh T on every improvement in `cautious()`; thread
scheduler and virtual-time both already do a 100× replay-hash check that becomes a test).

---

## 6. Crate layout

```
dowsing/                    (root; package still named `iterator-fuzz` — rename is D1)
  src/...                   CaseRng, curious/cautious, shrink, coverage traits, sancov (unchanged surface)
  src/stream.rs             #[doc(hidden)] StreamSpec / DetachedExecution (unified hooks, §5.2)

crates/dowsing-sandbox/     Linux-only. The supervisor and every model. One crate, feature-gated
  src/linux/{bpf.rs, notif.rs, ptrace.rs, mem.rs, shm.rs, fork.rs}   primitives (each spike has a copy today)
  src/supervisor/{loop.rs, thread.rs, dispatch.rs, table.rs}        §3.1–3.3
  src/sched.rs              §3.4                                    feature "sched"  (default on)
  src/clock.rs              virtual clock, waits, timers            feature "time"   (default on)
  src/net/{model.rs, fake_socket.rs, dns.rs}                        feature "net"
  src/fs/{vfs.rs, materialize.rs}, src/env.rs, src/entropy.rs, src/identity.rs   feature "fs"
  src/coverage.rs           SandboxCoverage: CoverageCapture over T's counters
  src/snapshot/{holder.rs, proto.rs, policy.rs}                     feature "snapshot"
  src/api.rs                Sandbox, SandboxBuilder, Ctx, Verdict, SandboxCost

crates/dowsing-target-rt/   Linked INTO the target (Mode A) or into the harness binary (Mode B).
  src/lib.rs                deps: libc only. __sanitizer_cov_* → shm counters + edge budget + yield marker;
                            announce syscall; mirror CaseRng byte source over shm cursor; crash handler
                            (_exit(128+sig) after header write); optional shared-page clock (§4.5)

crates/dowsing-sandbox-tests/   the spike demos as integration tests: buggy_stack under fork,
                            std/tokio client, lost_update/deadlock/missed_notify, backoff, sandboxed_config,
                            kv snapshot demo; replay-100× determinism assertions
```

Why sched/time/net/fs are **modules, not crates**: they share `Thread`, `Session`, the syscall
table and the clock; `waits` needs `net::Model` *and* `clock` *and* `sched`. Splitting them into
`dowsing-sched`, `dowsing-time`… would force a shared `dowsing-sandbox-core` with all the types
anyway and gain only compile-time. Features give the same opt-out. `dowsing-target-rt` *is* a
separate crate because it must have no dependency on the root crate and be linkable into non-Rust
build graphs (`cdylib`/`staticlib` for C/Go targets; `cargo` for Rust ones).

---

## 7. Public API sketch

```rust
// crates/dowsing-sandbox/src/api.rs
pub struct SandboxBuilder { .. }

impl SandboxBuilder {
    pub fn new() -> Self;
    /// Mode A: any executable. `argv[0]` is the path; env is virtualised (§3.2).
    pub fn binary(self, path: impl AsRef<Path>, args: &[&str]) -> Self;
    /// Mode B: run `body` in a forked child of the current process (requires dowsing-target-rt in the binary).
    pub fn in_process(self) -> Self;
    pub fn fs(self, f: impl FnOnce(&mut FsSpec)) -> Self;              // virtual root, static files, passthrough prefixes
    pub fn net(self, policy: NetPolicy) -> Self;                       // Disabled | Fake { dns: bool, families: .. }
    pub fn time(self, t: TimePolicy) -> Self;                          // Real | Virtual { epoch: SystemTime, quantum: Duration }
    pub fn sched(self, s: SchedPolicy) -> Self;                        // Native | Deterministic { budget_table: &[u32], max_decisions: usize }
    pub fn entropy(self, e: EntropyPolicy) -> Self;                    // Real | FromCase
    pub fn snapshots(self, p: SnapshotPolicy) -> Self;                 // Off | CautiousOnly(cost_cliff: Duration) | Always(..)
    pub fn wall_timeout(self, d: Duration) -> Self;                    // default 2 s
    pub fn pin_cpu(self, pin: bool) -> Self;                           // default true
    pub fn coverage(self, c: CoveragePolicy) -> Self;                  // None | Sancov { cmp_features: bool }
    pub fn build(self) -> io::Result<Sandbox>;                         // spawns forkserver, installs filter, probes kernel features
}

pub struct Sandbox { .. }                                              // one per supervisor thread; !Sync by design

impl Sandbox {
    /// Mode A. `drive` runs in the supervisor and draws every environment decision from `rng`
    /// through `ctx`; returns the harness's own verdict about the target's observable behaviour.
    pub fn run<C: CoverageCapture>(
        &mut self,
        rng: &mut CaseRng<C>,
        drive: impl FnMut(&mut Ctx<'_>, &mut CaseRng<C>) -> HarnessVerdict,
    ) -> Outcome;

    /// Mode B. `body` runs in the child; `rng` is mirrored over shm (§3.5).
    pub fn run_in_process<C: CoverageCapture>(
        &mut self,
        rng: &mut CaseRng<C>,
        body: impl FnMut(&mut CaseRng<C>) -> HarnessVerdict,
    ) -> Outcome;

    pub fn replay(&mut self, case: &Case, ..) -> Outcome;             // Case::replay() in a fresh T; used by cautious() check
    pub fn stats(&self) -> SandboxStats;                              // traps, stops, held, parked, fork µs, per-lane µs
}

/// What the harness sees while T runs (Mode A). Every method that takes a decision records a span.
pub struct Ctx<'a> { .. }
impl Ctx<'_> {
    pub fn fs(&mut self) -> &mut FsModel;         // add_file(path, bytes) / add_dir / fault(path, errno)
    pub fn net(&mut self) -> &mut NetModel;       // expect_connect(addr) -> Peer; Peer::reply(bytes) / refuse() / reset() / eof()
    pub fn clock(&mut self) -> &mut ClockModel;   // now() ; jump_policy(rng) ; deadline_hint(Duration)
    pub fn sched(&mut self) -> &mut SchedModel;   // decisions drawn lazily from rng; harness may pin a policy
    pub fn stdin(&mut self, bytes: &[u8]);
    pub fn wait(&mut self) -> Exit;               // run T to exit/crash/timeout/deadlock under the loop in §3.1
    pub fn cost(&self) -> SandboxCost;
}

pub struct Outcome {
    pub verdict: Verdict,                          // §5.5
    pub harness: HarnessVerdict,                   // Pass | Fail(String)
    pub cost: SandboxCost,
    pub transcript: Transcript,                    // Vec<Event> for printing the repro (net-intercept/thread-scheduler style)
    pub stats: CaseStats,                          // stops, traps, wall, virtual_elapsed, fork_us
}

/// `CoverageCapture` over the target's counters; `finish_capture` merges T's counters (+ cmp features if enabled).
pub struct SandboxCoverage { .. }
impl CoverageCapture for SandboxCoverage { type Token = CaseToken; /* start/finish/discard */ }
```

Target side:

```rust
// crates/dowsing-target-rt/src/lib.rs   (no_std-compatible core, libc only)
pub fn init();                                   // attach shm from env fd; install crash handlers; announce counters. No-op if not sandboxed.
pub fn yield_point();                            // explicit scheduling point for uninstrumented hot loops
pub fn checkpoint_hint();                        // "expensive setup done" → snapshot candidate
#[no_mangle] extern "C" fn __sanitizer_cov_trace_pc_guard(g: *mut u32);   // edge bitmap + budget decrement → marker syscall at 0
#[no_mangle] extern "C" fn __sanitizer_cov_8bit_counters_init(start: *mut u8, end: *mut u8);   // announce
#[no_mangle] extern "C" fn __sanitizer_cov_trace_cmp8(a: u64, b: u64);   // optional; off by default (cost §9)
```

---

## 8. What a user writes

### 8.1 Mode A: a real HTTP client binary against a fake peer under virtual time and a deterministic scheduler

```rust
use dowsing::{curious, cautious, Case};
use dowsing_sandbox::{SandboxBuilder, NetPolicy, TimePolicy, SchedPolicy, EntropyPolicy, HarnessVerdict, Verdict, PeerAction};

fn main() -> std::io::Result<()> {
    let mut sb = SandboxBuilder::new()
        .binary("target/release/my_client", &["--server", "api.example:7000"])
        .net(NetPolicy::Fake { dns: true })
        .time(TimePolicy::Virtual { epoch: EPOCH, quantum: Duration::from_micros(1) })
        .sched(SchedPolicy::Deterministic { budget_table: &[0, 1, 4, 16, 64], max_decisions: 64 })
        .entropy(EntropyPolicy::FromCase)
        .coverage(CoveragePolicy::Sancov { cmp_features: false })
        .build()?;

    let drive = |ctx: &mut Ctx, rng: &mut CaseRng<_>| {
        let peer = ctx.net().expect_connect("10.66.66.1:7000");     // records nothing yet
        let mut frames = rng.range(0..16);                          // range: number of peer events
        while let Some(item) = frames.next() {
            match item.variant(4) {                                 // variant: 0 = the boring answer
                0 => { let n = item.gen_range(0..=64); peer.reply(&item.bytes(n)); }   // payload bytes: raw draws
                1 => peer.would_block(),                            // readiness variant, evaluated at the next poll
                2 => peer.reset(),
                _ => peer.eof(),
            }
        }
        let exit = ctx.wait();                                      // runs the loop of §3.1; sched/time decisions are drawn lazily
        match exit { Exit::Code(0) | Exit::Code(1) => HarnessVerdict::Pass,
                     other => HarnessVerdict::Fail(format!("{other:?}")) }
    };

    for mut rng in curious().with_coverage(sb.coverage()).take(50_000) {
        let out = sb.run(&mut rng, drive);
        let bad = !matches!(out.verdict, Verdict::Passed) || out.harness.is_fail();
        if bad {
            let case: Case = rng.fork_case();
            let mut best: Option<Outcome> = None;
            for mut rng in cautious().with_case(case).with_coverage(sb.coverage()).take(4_000) {
                let out = sb.run(&mut rng, drive);
                let still_bad = !matches!(out.verdict, Verdict::Passed) || out.harness.is_fail();
                if matches!(out.verdict, Verdict::SupervisorError(_)) || !still_bad { rng.discard(); continue; }
                rng.coverage_with_cost(out.cost.total());           // events + non-default variants + bytes + virtual time
                best = Some(out);
            }
            println!("{}", best.unwrap().transcript);               // "connect(1000, 10.66.66.1:7000) -> Ok; send 15 bytes; recv <- Reset; T1 picked over T0 …"
            return Ok(());
        }
        rng.coverage_with_cost(out.cost.total());
    }
    Ok(())
}
```

### 8.2 Mode B: today's `buggy_stack` harness, sandboxed, unchanged body

```rust
let mut sb = SandboxBuilder::new().in_process().entropy(EntropyPolicy::FromCase).build()?;
for mut rng in curious().with_coverage(sb.coverage()).take(8192) {
    let out = sb.run_in_process(&mut rng, |rng| {
        let mut ops = Vec::new();
        let mut items = rng.range(0..80);                            // shrink-quality's structured buggy_stack
        while let Some(item) = items.next() { ops.push(Op::sample(item)); }
        match check_stack(&ops) { Ok(()) => HarnessVerdict::Pass, Err(e) => HarnessVerdict::Fail(e) }
    });
    if out.harness.is_fail() || matches!(out.verdict, Verdict::Crashed { .. } | Verdict::Panicked(_)) {
        let case = rng.fork_case();
        /* cautious() exactly as in examples/buggy_stack.rs; `rng.coverage_with_cost(ops.len())` */
    }
}
```

`dowsing_target_rt::init()` is called once at the top of `main` (a no-op when not sandboxed), and
the binary is built with the sancov flags from the README. A `#[dowsing::sandboxed]` test
attribute that does the fork + `init()` dance is a later convenience (D6).

---

## 9. Performance budget (measured → projected)

| Item | Measured | Source | Unified design |
|---|---|---|---|
| unotify round trip, pinned / unpinned | 2.43 µs / ~8 µs | fs-env `latency` today; net-intercept bench | same |
| unotify `CONTINUE` passthrough | +3.5 µs/open pinned | fs-env today | same; keep the fake-fd BPF guard so real fds pay 0 |
| ptrace syscall stop (RET_TRACE, skip + setregs + cont) | 10.7–11.1 µs | thread-scheduler README; vt 10 030 reads/98.7 ms today | same; only the wait/clock/thread family pays it |
| fork + filter + handoff + exit + reap | 199 µs @2 MiB; 116/341 µs @1/10 MiB | net-intercept README; coverage-bridge README | same; dominates cheap targets — hence 1.2–2 k cases/s ceiling for one-shot targets, 17 k/s only when the target stays resident (fs-env in-process number will **not** carry over) |
| coverage decode (inline 8-bit, no cmp / cmp) | 4.5 µs / 16–24 µs per case | coverage-bridge today | same; cmp features off by default |
| in-process sancov+cmp fuzzer overhead | 406 exec/s vs 858 bridged | coverage-bridge today | the bridge is *faster* than in-process because the fuzzer's own comparisons are no longer instrumented |
| trapped clock read | ~11 µs (vs ~20 ns vDSO) | vt today | shared-page fast path (§4.5) required for clock-hot targets |
| scheduler overhead on demos | 1.7–1.9× native wall | thread-scheduler README | same |
| snapshot continuation | p50 0.43 ms @10 MiB, 2.1 ms @100 MiB (incl. 64 ops) | snapshot-rewind today | only where prefix > that |

Expected steady-state for a resident-forkserver Rust target under all four models (fork 0.2 ms +
~30 traps × 2.4 µs + ~10 stops × 11 µs + decode 5 µs): **≈ 0.4 ms/case ≈ 2 500 cases/s per CPU,
≈ 15–20 k/s on 8 pinned CPUs.** Targets that spin on the clock or take thousands of scheduling
stops per case will be 10–50× slower until §4.5 lands.

---

## 10. Roadmap (dependency-ordered; effort in Devin sessions)

| # | Step | Depends on | Unblocks | Sessions |
|---|---|---|---|---|
| 0 | **Merge `shrink-quality` into main** (reducer changes + structured `buggy_stack` + README notes). Unify the coverage-bridge and snapshot-rewind root hooks into `dowsing::stream` (§5.2). Rename package (D1). | — | everything; `cautious()` quality for all later spans | 1 |
| 1 | **`dowsing-sandbox` skeleton + `dowsing-target-rt`**: linux primitives deduplicated from the 4 copies (bpf/notif/ptrace/mem/shm/fork), single syscall table → one BPF program, forkserver (fork-per-case + exec fallback), shm layout with shared cursor + span ring, crash export, verdicts, `SandboxCoverage`. Port `buggy_stack_bridge` as the first integration test (Mode B). | 0 | every model; crash-shrink (§5.5) | 2 |
| 2 | **Supervisor loop + per-thread state** (§3.1–3.3): epoll over notif fd + signalfd + pidfds; `Thread` map; both lanes → `Event`; `PTRACE_O_TRACECLONE/EXEC/EXIT/EXITKILL`; pinning; wall timeout. No models yet — passthrough only. Assert: `buggy_stack` under passthrough within 10 % of step 1. | 1 | 3–6 | 1 |
| 3 | **fs/env/entropy/identity models** ported from fs-env into the unotify lane; `Isolation::Fork` (the piece fs-env did not build) is free now. Port `sandboxed_config` as a test (target: ≥ 2 k cases/s under fork; 17 k/s is unreachable with fork-per-case and should not be the bar). | 2 | 4 (fake fds share the fd-table code), 7 | 1–2 |
| 4 | **Scheduler** (§3.4): port thread-scheduler (futex emulation, marker, deadlock detection, `target-rt` edge budget); extend futex ops (`WAIT_BITSET`, `REQUEUE`, `futex_waitv`); port the 3 demo targets + 100× replay-hash test. | 2 | 5 (time needs one runnable thread), 6 | 2 |
| 5 | **Virtual clock + waits** (§3.2 rows "readiness", "sleeping", "clock", "timers"): port virtual-time; auxv rewrite at exec; `poll*/epoll*/select*` in the ptrace lane with fake-fd hook for step 6; quiescence rule; time-jump `variant`s in the scheduler's decision stream. Port `backoff_*` tests incl. tokio `--multi` **now expected 100/100**. | 4 | 6, 8 | 2 |
| 6 | **Network model**: port net-intercept (fake fds, socketpair data plane, DNS, `fdinfo` epoll scan) into the unotify lane; readiness gating via step 5's `waits`; held-notification parking (§3.3 inv. 2); `select/pselect6` gating (spike gap). Port std/tokio client + server tests. | 3, 5 | Mode A end-to-end (§8.1) | 2 |
| 7 | **Shared-page clock fast path + `LD_PRELOAD` shim for glibc targets** (§4.5); measure `probe_target` ≤ 2× native. | 5 | clock-hot targets (tokio timers, backoff loops) | 1–2 |
| 8 | **Snapshots**: port holder tree + policy; snapshot `Session`; `CautiousOnly` default; per-holder tmpfs subdir; replay-equivalence test; fill the stub tests (`fd_refusal`, `replay_equivalence`). | 3, 4 (single-thread refusal), 6 (socket state is supervisor state) | expensive-setup targets in `cautious()` | 2 |
| 9 | **Parallel**: one `Sandbox` per CPU behind `ParallelCases`/rayon; corpus merge; `SandboxStats` aggregation. Measure 8-CPU scaling on `buggy_stack` and `std_client`. | 1–6 | throughput | 1 |
| 10 | **Fidelity backlog** (ordered by likely need): `SCM_RIGHTS`/`dup` of fake fds; AF_INET socket options fidelity vs AF_UNIX (or netns alternative, D5); signals as scheduling events; `timer_create`/`setitimer`; cmp-hook `memcmp/bcmp` in root sancov (fs-env `--raw` finding); musl/static targets test matrix. | 6 | real-world targets | 3+ (open-ended) |

Critical path: 0 → 1 → 2 → 4 → 5 → 6 (≈ 10 sessions to Mode A end-to-end). Steps 3, 7, 8, 9 are
off the critical path and parallelisable across child sessions once step 2 exists.

---

## 11. Decisions Evan must make

* **D1 — Package/crate names.** Root package is `iterator-fuzz` while the README says dowsing.
  Proposal: rename to `dowsing`, add `dowsing-sandbox`, `dowsing-target-rt` in a workspace.
  Needed before step 1 to avoid a second rename.
* **D2 — Fork-per-case is the only isolation.** Accept the ~0.2–0.35 ms floor (≈ 2–3 k cases/s
  per CPU for cheap targets) in exchange for crash isolation, clean env, and snapshot compatibility.
  Alternative kept as a fallback only: in-process thread-scoped filter (fs-env) for targets that
  are known crash-free — I recommend *not* exposing it in v1.
* **D3 — Scheduler preemption granularity requires `trace-pc-guard` in the target.** Without it,
  preemption happens only at syscalls (Loom-style yield points are lost). Decide whether
  `dowsing-target-rt` is mandatory for Mode A Rust targets (I recommend yes) and whether to
  accept syscall-only preemption for C/Go/uninstrumented binaries (I recommend yes, documented).
* **D4 — Clock fast path scope (step 7).** Shared page + `target-rt` symbol for Rust targets only,
  or also an `LD_PRELOAD` shim for glibc/dynamic targets? The shim is the only place `LD_PRELOAD`
  appears in this design; skipping it keeps the design mechanism-pure at 11 µs/clock read.
* **D5 — AF_UNIX socketpair emulation of AF_INET vs a real network namespace.**
  `unprivileged_userns_clone=1` here, so `unshare(CLONE_NEWUSER|CLONE_NEWNET)` + loopback would
  give real TCP semantics (options, `getsockname`, `SO_ERROR`) with the supervisor holding real
  peer sockets — but readiness and ordering then come from the kernel and must still be forced
  through the scheduler. Measured path is socketpair (works with std and tokio). Recommend
  socketpair for v1; netns as a step-10 fidelity option.
* **D6 — Harness ergonomics.** Whether to add a `#[dowsing::sandboxed]` test attribute /
  `dowsing::main` wrapper that performs the fork + `init()` (libtest runs tests on threads, which
  breaks single-thread fork assumptions — snapshot-rewind R2).
* **D7 — Default `wall_timeout` and `MAX_PREFIX_LEN`.** 2 s wall per case (all spikes) and the
  4 KiB prefix cap: environment-heavy cases (many files/events) approach 4 KiB; raising the cap
  changes `Case` serialisation.
* **D8 — cmp feedback default.** Cross-process cmp features cost 16–24 µs/case decode and
  ~600 µs/case sort/dedup on the supervisor side (coverage-bridge). Off by default, on for
  string/config-shaped inputs (fs-env `--raw` needed it and even then lacked `memcmp` hooks)?
* **D9 — Which spike branches to close.** All seven can be closed after step 0/1 land; their
  crates move to `crates/dowsing-sandbox-tests` as integration tests, not kept as `spikes/`.

---

## 12. What did not work, what was not reproduced, open risks

### 12.1 Did not work / known gaps (observed)

* **Multithreaded targets under virtual time alone are nondeterministic**: tokio `--multi` replay
  0/100 identical event-log hashes, 44/100 same outcome (today). Only the scheduler fixes it.
* **Crash cases do not shrink** in coverage-bridge: minimisation of the `BUGGY_STACK_ABORT=1`
  case ended at "0 ops, 4096 bytes" (today) because spans are exported only at normal case end.
  §5.5 is the fix; it is not built.
* **`curious()` gets nothing from snapshots** (0/400 continuations today); only `cautious()`
  benefits (198/200). The snapshot-rewind crate's `curious` demo also panics inside the KV target
  (`range start index 320 out of range` in `kv.rs:123`) — a demo-target bug, not a supervisor
  bug, but it means the "curious with snapshots" measurement in its DESIGN §10.4 was never
  obtained. Its `tests/*.rs` are empty stubs.
* **fs-env in-process mode** cannot survive a target crash and leaks `setenv`; `Isolation::Fork`
  was designed but not built. Flat-byte config (`--raw`) does not find the demo bug because the
  root `sancov.rs` has no `memcmp/bcmp` hooks.
* **fs-env's 17 k cases/s will not survive fork-per-case**; the honest ceiling with the unified
  design is ~2–3 k/s for that demo.
* **Spikes overlap on `poll*/epoll*/select*/getrandom/futex/nanosleep`** with different seccomp
  actions; stacked as-is, the ptrace spikes would never see those syscalls (§4.2).
* **net-intercept gaps** (README): `select/pselect6` not gated, fake-fd `SCM_RIGHTS`/`dup`
  escape, AF_UNIX ≠ AF_INET semantics, DNS only tested with glibc, timeout cases lose coverage.
* **thread-scheduler gaps** (README): futex op subset; preemption only in instrumented code; no
  signal scheduling; timed `poll/epoll/select` not emulated (virtual-time does that — hence the
  merge order).
* **virtual-time gaps** (README): `timer_create`/`setitimer`/`alarm` incomplete; shared-page fast
  path unbuilt; blocking syscalls outside its table are invisible to the quiescence rule.
* **Clippy**: two pre-existing warnings on the base (`manual_isolate_lowest_one`,
  `while_let_on_iterator`).

### 12.2 Not independently reproduced here

* Spike-reported numbers I did not re-run: unotify 7.65 µs and ptrace 30 µs/pair from
  coverage-bridge; forkserver 116/341 µs by RSS; net-intercept 2.6 µs pinned / 199 µs fork;
  fork-vs-RSS table and THP 10× from snapshot-rewind §1.1; `ptrace`-injected fork 1.5–1.8 ms;
  userfaultfd WP with `UFFD_USER_MODE_ONLY`; 20-seed matrices for the scheduler (`seeds` mode);
  fs-env `--no-pin` 7 388/s; the ~600 µs/case cmp sort/dedup profile.
* Any target that is not one of the spike demos: no real HTTP client, no Go/C binary, no musl or
  static binary, no target with >3 threads, no target with an RSS >100 MiB under the sandbox.
* Rayon/`ParallelCases` with any sandbox (no spike measured multi-CPU scaling).
* Coexistence of *all* lanes on one target in one process. Each pairwise fact in §4.1 comes from
  a different spike; the combination is design, not measurement, until step 2.

### 12.3 Open risks

1. **Held-notification vs ptrace interference** (§3.3 inv. 2) is reasoned from seccomp(2) and the
   spikes' `SEND retries = 0` counters, not tested under a scheduler that also `INTERRUPT`s. If
   `PTRACE_INTERRUPT` cancels held notifications in practice, `WouldBlock` on blocking fake fds
   must move to the ptrace lane (cost: one more 11 µs stop per blocking recv; design unchanged).
2. **Kernel state that neither lane sees**: `io_uring` is rejected; `AIO`, `SIGIO`, `inotify`,
   `eventfd` written by the kernel, `SO_TIMESTAMP` and `vDSO getcpu/time` fallback paths are not
   modelled. Each is a nondeterminism source that shows up as a failed replay check
   (`discard()`), not as a wrong answer — provided the replay check runs.
3. **Determinism of the target's own address-dependent behaviour** (`HashMap` `RandomState`
   seeded from `getrandom` — covered; pointer hashing/ASLR — not). ASLR must be disabled for T
   (`personality(ADDR_NO_RANDOMIZE)` at exec, as `setarch -R` did in shrink-quality).
4. **Fork cost on large targets**: 4.2 ms at 1 GiB RSS without THP (snapshot-rewind). A
   long-lived server with a big heap fuzzed fork-per-case is ~200 cases/s; snapshots (step 8)
   are the mitigation, and they require single-threadedness at checkpoint.
5. **Scope creep in syscall fidelity** (step 10 is open-ended). Mitigation: every unmodelled
   syscall is `ALLOW`, so the sandbox degrades to "less deterministic", never to "broken";
   the replay check is what turns that into a `discard()`.
6. **`ptrace_scope`/seccomp availability on other hosts**: everything here needs
   `ptrace_scope ≤ 1` (parent→child) and kernel ≥ 5.9 (`ADDFD`); `sync_wake_up`, `addfd`,
   `pidfd_getfd` were all present here (`probe_features()`; `SYNC_WAKE_UP` needs ≥ 6.6 and is
   the difference between 2.4 and ~8 µs); container runtimes commonly restrict `ptrace` and
   nested seccomp filters. Not tested on any other host.
7. **Two root-crate hook sets** (coverage-bridge, snapshot-rewind) drift if step 0 is skipped;
   they touch `rng.rs` in overlapping places (`fill_budget` vs `snapshot_install_stream`).
