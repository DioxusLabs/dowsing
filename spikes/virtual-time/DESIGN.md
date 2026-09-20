# Spike: deterministic virtual clock (`virtual-time`)

Status: design memo, no prototype yet. Everything below that is labelled **measured** was checked
on the box this memo was written on (Ubuntu 22.04, kernel 6.8.0-1061-aws, glibc 2.35, Rust 1.98.1,
`ptrace_scope=1`, 8 cores) with throwaway C/Rust programs (~300 lines total; the relevant parts are
reproduced in the appendix). Everything else is labelled as inference or as prior art.

## 1. Goal restated

Make time a fuzzer input. The target runs unmodified inside a supervised sandbox; every way it can
observe or wait on time is answered by the supervisor from a *virtual clock* that

* only advances when every thread of the target is blocked (or by a small deterministic quantum
  per clock read so busy-wait loops terminate), and
* advances by amounts chosen from the `CaseRng`, so `curious()` can explore "what if this sleep
  overshot by ten minutes" and `cautious()` can shrink the schedule back to "the one jump that
  matters".

Success: a demo with a timeout/retry/backoff bug that needs minutes of wall-clock to show up is
found in milliseconds, replays byte-for-byte, and the memo says which approach covers
`std::time::Instant`/`SystemTime`, `std::thread::sleep`, `Condvar::wait_timeout` & friends, and
tokio timers.

## 2. What the target actually does (measured)

Before choosing an interception layer it matters *which* syscalls Rust and tokio use. `strace -f`
on small probes (glibc 2.35, tokio 1.53 / mio 1.2):

| Rust API | Kernel interface actually used |
| --- | --- |
| `Instant::now()` | `clock_gettime(CLOCK_MONOTONIC)` via the **vDSO**: 1 M calls, 0 syscalls, ~51 ns/call |
| `SystemTime::now()` | `clock_gettime(CLOCK_REALTIME)` via the vDSO |
| `thread::sleep(d)` | `clock_nanosleep(CLOCK_MONOTONIC, 0 /*relative*/, {d}, &rem)` |
| `thread::park_timeout`, `Condvar::wait_timeout`, `mpsc::recv_timeout` | `futex(addr, FUTEX_WAIT_BITSET_PRIVATE, val, {abs CLOCK_MONOTONIC deadline}, FUTEX_BITSET_MATCH_ANY)`; realtime variant adds `FUTEX_CLOCK_REALTIME` |
| tokio `current_thread`: `sleep`, `timeout` | `epoll_wait(epfd, evs, 1024, timeout_ms)`; the timer wheel itself uses `Instant::now()`; the next deadline is rounded *up* to whole ms (30 ms sleep → `epoll_wait(.., 31)`) |
| tokio `multi_thread` | same `epoll_wait(.., ms)` on whichever worker holds the driver; parked workers use `futex(.., NULL timeout)` |
| musl static-pie binary (`x86_64-unknown-linux-musl`) | same syscalls; musl also finds the vDSO through `AT_SYSINFO_EHDR` |

Nothing in std or tokio uses `timerfd`, `setitimer`, `alarm`, `select`, `poll` timeouts or
`epoll_pwait2` today; they still have to be covered for C dependencies and future mio versions, but
they are not on the demo's critical path.

Two consequences drive the design:

1. **Clock reads never enter the kernel.** Any syscall-level interception is blind to
   `Instant::now()` unless the vDSO is dealt with first.
2. **Waits are a small closed set** (`clock_nanosleep`, `nanosleep`, `futex` with timeout,
   `epoll_wait`/`epoll_pwait`/`epoll_pwait2`, `poll`/`ppoll`, `select`/`pselect6`,
   `timerfd_settime`) and all of them carry either a relative duration or an absolute
   `CLOCK_MONOTONIC`/`CLOCK_REALTIME` deadline that a supervisor can translate into a virtual
   deadline.

## 3. Recommended approach

**A ptrace supervisor with a seccomp `SECCOMP_RET_TRACE` filter, vDSO neutralised at the exec stop,
time syscalls emulated at a single seccomp stop, blocking waits turned into zero-timeout probes
whose threads the supervisor parks, and the virtual clock advanced at quiescence by a decision drawn
from the `CaseRng`.** The supervisor lives in the harness process; the target is an unmodified
(sancov-instrumented) binary that never links the fuzzing API.

### 3.1 Interception layer: seccomp filter + ptrace

* The child does `PTRACE_TRACEME`, installs a BPF filter (`no_new_privs` + `seccomp(SET_MODE_FILTER)`)
  that returns `SECCOMP_RET_TRACE` for the time-related syscall numbers and `SECCOMP_RET_ALLOW` for
  everything else, raises `SIGSTOP`, then `execve`s the target. The parent sets
  `PTRACE_O_TRACESECCOMP | TRACEEXEC | TRACECLONE | TRACEFORK | TRACEVFORK | TRACEEXIT | EXITKILL |
  TRACESYSGOOD`. Filters are inherited across `exec`, `fork`, and `clone`, and `TRACECLONE`
  auto-attaches new threads, so multi-threaded targets are covered with no per-thread work.
  **Measured:** works unprivileged with `ptrace_scope=1` (we are the parent).
* Only filtered syscalls stop the tracee. All other syscalls run at native speed (this is what
  strace's `--seccomp-bpf` and gVisor's old ptrace platform do).
* **Single-stop emulation (measured):** at the `PTRACE_EVENT_SECCOMP` stop, `PTRACE_SETREGS` with
  `orig_rax = -1` and `rax = <return value>` makes the kernel skip the syscall and return `rax`
  unchanged; no syscall-exit stop is needed (`do_syscall_64` leaves `regs->ax` alone for
  `nr == -1`). Emulating `clock_gettime` this way costs **~10.1 µs per call** (2 M calls: 20.2 s).
  The floor for a seccomp stop + `PTRACE_CONT` with no register traffic is **~7.8 µs**. Native
  vDSO is 51 ns, so a target that hammers `Instant::now()` in a hot loop is ~200× slower under the
  sandbox. Section 3.6 has the fast path; for the demo it does not matter (a run is ~30 stops).
* Tracee memory is read/written through `/proc/<pid>/mem` (`pread`/`pwrite`). Note the fd is bound
  to the `mm` it was opened on and must be (re)opened after the `PTRACE_EVENT_EXEC` stop — the
  first experiment failed on exactly this.

### 3.2 The vDSO problem: hide `AT_SYSINFO_EHDR` (primary), patch the vDSO (fallback/fast path)

Three options were on the table; two were verified, one is rejected.

**Hide the vDSO from the auxiliary vector (recommended, measured).** At the `PTRACE_EVENT_EXEC`
stop nothing has executed yet (not even `ld.so`) and `rsp` points at `argc`. Walk
`argc, argv…, NULL, envp…, NULL, auxv` and overwrite the `AT_SYSINFO_EHDR` entry's type with
`AT_IGNORE` (one 16-byte `pwrite`). glibc's `dl_vdso_vsym` then finds no vDSO and every
`clock_gettime`/`gettimeofday`/`time` becomes a real syscall, which hits our filter. Verified with:

* glibc dynamic Rust binary: 1 M `Instant::now()` → 2 M intercepted `clock_gettime`, program
  reports `1M Instant::now in 0ns` (clock frozen at 0);
* musl static-pie Rust binary: `sleep`/`park_timeout` emulated identically;
* tokio `current_thread` and `multi_thread` demos: 30 ms sleep + 20 ms timeout report
  `elapsed 50ms` exactly, in ~2 ms wall time, 34/63 stops.

Nothing else in glibc broke (it just uses the syscall fallbacks for `time`, `getcpu`,
`gettimeofday`). A useful side effect: on newer kernels/glibc (6.11+/2.41+) hiding the vDSO also
disables `vgetrandom`, so entropy goes through `getrandom(2)` and is interceptable by the same
mechanism. The Go runtime also falls back to syscalls without `AT_SYSINFO_EHDR` (inference from
`runtime/vdso_linux.go`, not measured).

**Patch the vDSO text in the tracee (measured, keep as fast path).** The vDSO image is identical in
every process, so the supervisor parses *its own* vDSO (`getauxval(AT_SYSINFO_EHDR)`, `.dynsym`)
to get the offsets of `__vdso_clock_gettime`/`__vdso_gettimeofday`/`__vdso_time` and `pwrite`s
`mov eax, NR; syscall; ret` over them at the tracee's base. Writing to the r-x vDSO mapping through
`/proc/pid/mem` succeeds (FOLL_FORCE does a COW break; this is what rr relies on) and the patched
tokio demo behaves identically to the auxv-hidden one. This is the door to a trap-free clock
(section 3.6) and the only option for a `fork()`-without-`exec` tracee where there is no exec stop.

**`LD_PRELOAD` (rejected as the mechanism).** libfaketime-style interposition of `clock_gettime`
etc. works for glibc-dynamic Rust binaries but: does not exist for static/musl targets; misses
glibc-internal hidden aliases (`__clock_gettime64` used by `pthread_cond_timedwait`, `sleep`…);
Rust's futex path goes through `libc::syscall(SYS_futex, …)`, so you would have to interpose the
variadic `syscall()` and dispatch on the number; and, decisively, it cannot implement "advance only
when all threads are blocked" because it has no view of the kernel-side wait. It may come back later
as an *optional* in-process accelerator (section 3.6), never as the source of truth.

### 3.3 Emulating the clocks

The supervisor keeps `vnow` (virtual `CLOCK_MONOTONIC`, starts at a fixed constant such as
`1_000 s` so `Instant` arithmetic never underflows) and `realtime_base` (captured once at spawn or
fixed for reproducibility; virtual `CLOCK_REALTIME = realtime_base + vnow + realtime_step`).

| Syscall | Emulation |
| --- | --- |
| `clock_gettime(clk, ts)` | write `timespec` for `clk` (`REALTIME*` → realtime; `MONOTONIC*`, `BOOTTIME*` → `vnow`; `*CPUTIME*` → `vnow` for now); return 0 |
| `gettimeofday`, `time` | same, realtime |
| `clock_getres`, `clock_adjtime`, `settimeofday`, `adjtimex` | pass through / `EPERM` |
| every emulated read | `vnow += read_quantum` (default 1 µs, per-run choice, see §5) so `while Instant::now() < deadline {}` terminates |

`vnow` therefore never goes backwards; `realtime_step` may (an NTP step is a legitimate thing to
fuzz; `SystemTime::elapsed()` returning `Err` is a classic bug source).

### 3.4 Emulating waits: probes and parking

Every blocking call with a timeout is handled with the same three-step pattern, which is exact
(no heuristics) and never lets the kernel do a timed wait:

1. **Translate** the argument into a virtual deadline `D` (relative → `vnow + d`; absolute →
   as-is on the matching virtual clock; `FUTEX_CLOCK_REALTIME` respected).
2. **Probe**: rewrite the registers so the kernel performs the *same* operation with a zero
   timeout, and resume with `PTRACE_SYSCALL` so we get the exit stop.
   * `futex(WAIT/WAIT_BITSET, timeout=T)` → keep everything, point the timeout at an
     all-zero `timespec` (for `WAIT_BITSET` absolute time 0 is in the past). `EAGAIN` means the
     value changed → return it verbatim. `ETIMEDOUT` means "would block".
   * `epoll_wait`/`epoll_pwait` → `timeout = 0`; `epoll_pwait2`/`ppoll`/`pselect6` → point at a
     zero `timespec`; `poll` → `0`; `select` → zero `timeval`. `> 0` → return verbatim;
     `0` → "would block".
   * `nanosleep`/`clock_nanosleep` → no probe, straight to step 3 (return 0, or `rem = 0`).
3. **Park**: on "would block" do **not** resume the thread. Record
   `Parked { tid, kind: Futex(addr) | Epoll(epfd) | Poll(fds) | Sleep, deadline: Option<D> }`.

Threads are un-parked by exactly three events, all observed by the single-threaded supervisor in a
deterministic order:

* **Wake by another thread.** `FUTEX_WAKE(addr, n)` / `FUTEX_REQUEUE` are filtered too: the
  kernel wake runs (it finds nobody, our waiters are parked), then the supervisor completes up to
  `n` parked `Futex(addr)` waiters with `rax = 0` (FIFO by park time) and reports the count to the
  waker. Protocol correctness holds because the probe is atomic with respect to the futex word and
  the supervisor serialises probe-exit and wake-entry stops.
* **Readiness of a file descriptor.** The supervisor duplicates the tracee's epoll fd (or the
  polled fds) with `pidfd_getfd` — **measured:** works unprivileged for the tracer and
  `epoll_wait` on the stolen epfd sees the child's readiness — and adds it to its own event loop.
  When it becomes ready the parked thread is completed by re-issuing its original syscall with a
  zero timeout (rewind `rip -= 2` and restore `rax = orig_rax`, the standard ptrace restart trick),
  so the tracee gets real events written by the kernel.
* **Virtual deadline.** See §3.5.

Because parked threads are not inside the kernel, `PTRACE_INTERRUPT`/`ERESTART*` rewriting (the
hard part of rr's desched handling) is never needed.

`timerfd` is the one wait primitive that cannot be probed, because its deadline is observed through
`epoll`. Plan: filter `timerfd_settime`/`timerfd_gettime`, record the virtual expiry per fd, disarm
the real timer, and when the virtual clock reaches the expiry arm the supervisor's `pidfd_getfd`
duplicate with a 1 ns relative timeout so it becomes readable, then run the fd-readiness path. Not
needed for Rust std or tokio; scheduled last.

Threads blocked in *unsupervised* syscalls (`read` on a pipe, `accept`, `waitpid`…) are "blocked
externally". They are out of this spike's scope (network/files spike) but the model must tolerate
them: they count as blocked for quiescence, and if the clock is advanced while one of them later
completes, determinism is lost. The prototype records this as `Outcome::Nondeterministic` rather than
pretending.

### 3.5 Advancing the clock: quiescence and fuzzer decisions

A **quiescent point** is reached when every traced thread is parked or externally blocked. The
supervisor then:

1. Collects the sorted set of pending virtual deadlines `d₁ < d₂ < …` (sleeps, futex timeouts,
   poll timeouts, timerfds).
2. If there are none and every thread is parked on a wake/readiness that can only come from the
   target itself → **deadlock**: the run ends with `Outcome::Hang` (a finding in its own right).
3. Otherwise draws a **jump decision** from the `CaseRng` (§5) and sets `vnow` accordingly: the
   default (`variant == 0`) is `vnow = d₁` — exactly what `tokio::time::pause()` auto-advance does.
   Non-zero variants model a stalled machine: jump to `d₂`, `d₃`, or overshoot `d₁` by a drawn
   magnitude (µs/ms/s/min buckets). Every sleeper whose deadline is `≤ vnow` is completed
   (`ETIMEDOUT`/`0` as appropriate), in deadline order.

Runnable threads that were completed are resumed one at a time in a fixed order in the prototype;
choosing *which* one to resume is the deterministic-scheduling spike, and this design intentionally
leaves that hook (`fn pick_runnable(&mut self, rng)`) as the seam between the two spikes. For the
demo (single-threaded, and tokio `current_thread`) the order is trivial and replay is exact.

### 3.6 Performance path (not needed for the demo, designed in)

* Clock reads through a trap cost ~10 µs (measured). For hot targets: at exec time inject an
  `mmap(memfd)` into the tracee (rr/gVisor-style injected syscall) to map a shared page, and patch
  `__vdso_clock_gettime` with code that reads `vnow` from that page and does
  `lock xadd [page.vnow], read_quantum`. Clock reads then cost tens of ns, remain deterministic for
  a single running thread, and the supervisor still owns the jumps. The vDSO write path is already
  verified.
* Alternative with the same effect and less patching: gVisor systrap-style `SECCOMP_RET_TRAP`
  with an in-process `SIGSYS` handler reading the shared page (~1 µs). Needs code inside the target
  (preload or shim), so it is optional.
* Waits are inherently rare (≥ 1 per scheduling point), so their trap cost is irrelevant.

### 3.7 Coverage from the sandboxed target

`SancovCoverage` today reads counters in-process. For the sandbox:

* The target is built with the same recipe (`-Cpasses=sancov-module` + `inline-8bit-counters` +
  `pc-table` + `trace-compares`) and links `dowsing` only for the sancov callback symbols it must
  define anyway (a `target` cargo feature that compiles nothing but `src/sancov.rs`'s callbacks, or
  a 30-line `dowsing-sancov-stubs` crate).
* On `__sanitizer_cov_8bit_counters_init(start, stop)` the target announces the range with a
  reserved syscall number (`syscall(0x4d0_0001, start, stop)`, rr calls these "rrcalls"); the filter
  traps `nr ≥ 0x4d0_0000` and the supervisor records the ranges and returns 0. This avoids parsing
  the target ELF for `__start___sancov_cntrs`, which is the alternative if we ever want zero
  target-side code.
* At `exit_group` (filtered) or at the fatal-signal stop (`SIGABRT`/`SIGSEGV`), the supervisor
  `pread`s the counter ranges, buckets hit counts exactly like `counter_coverage()` in
  `src/sancov.rs`, and turns them into an `ExecutionFeedback`. Comparison features and dictionary
  values stay in-process for now (they live in thread-locals in the target); shipping them through
  a shared page is follow-up work.
* `SandboxCoverage: CoverageCapture` is a thin adapter: `start_capture` clears a slot,
  `Sandbox::run` fills it, `finish_capture` drains it. The `-Cinstrument-coverage`
  (`LlvmCoverage`) backend can get the same treatment later via `__llvm_prf_cnts`.

## 4. Alternatives considered and rejected

| Alternative | Why not (for this spike) |
| --- | --- |
| **`LD_PRELOAD` interposition (libfaketime)** | Misses static/musl, glibc-internal aliases, raw `syscall()`; cannot see "all threads blocked"; needs a dynamic target. Good accelerator, wrong foundation. See §3.2. |
| **Pure seccomp user-notif (`SECCOMP_RET_USER_NOTIF`), no ptrace** | **Measured** to work unprivileged here (supervisor answered `getppid` with 4242). But it cannot rewrite arguments/registers (only return value or `CONTINUE` with the original args), cannot touch auxv at exec, and cannot park a thread that must be woken by a kernel event without reimplementing the wait. Advantages (multiple supervisors, works with gdb attached, ~µs cost) do not outweigh that. Keep as a possible later platform for the *network/files* syscalls where it is a natural fit. |
| **`PTRACE_SYSCALL`/`SYSEMU` on every syscall (no seccomp filter)** | Two stops per syscall for *all* syscalls; strictly slower than the filter with no upside. |
| **Time namespaces (`CLONE_NEWTIME`)** | **Measured** available unprivileged (`unshare -Ur --time`), but only *offsets* `CLOCK_MONOTONIC`/`BOOTTIME`, cannot touch `CLOCK_REALTIME`, cannot freeze or jump on demand, and offsets are fixed before the first process enters. Useful only to make the monotonic epoch look realistic; not a virtual clock. |
| **rr-style full record/replay** | rr records real time and replays it; it does not virtualise time, and dragging in perf-counter based desched/ticks is far more than this spike needs. Its vDSO monkeypatching and injected-syscall tricks are borrowed. |
| **Hypervisor / KVM TSC control (Antithesis, Nyx/kAFL)** | Out of scope by requirement (local, no KVM snapshotting). Antithesis is the proof that "time as an input to the schedule" finds real bugs, which is the semantics adopted here. |
| **Library-level virtual time (`tokio::time::pause`, madsim, turmoil, sled's simulation)** | Requires the target to be written against the mock; contradicts "nothing has to be mocked". Their semantics (auto-advance when idle; shrinkable choice sequences) are the model for §3.5. |
| **eBPF / kprobes / uprobes / `bpf_override_return`** | Root and kernel config required. |
| **Binary rewriting / Frida-style hooks of `clock_gettime` callers** | Same coverage gaps as `LD_PRELOAD` with more moving parts. |
| **Fully emulating `futex` in the supervisor** | Unnecessary: the zero-timeout probe gives us atomicity for free and the kernel keeps doing the compare. |

## 5. Integration with dowsing's API

### 5.1 Where the `CaseRng` lives

The `CaseRng` stays in the **harness process**. The target draws nothing from dowsing; every
non-determinism it could observe is a syscall the supervisor answers from the harness's `CaseRng`:

* `getrandom(buf, n, flags)` → `rng.fill_bytes` (a `DrawKind::Bytes` span; capped by the
  4096-byte `MAX_PREFIX_LEN`, so the supervisor fills at most e.g. 256 bytes from the trace and
  the rest from a `SmallRng` seeded from the first 8 — `rand::rng()` seeds once with 32 bytes, so
  this is plenty). This is what makes a `rand`-using target fuzzable with zero code changes.
* time-jump and quantum decisions → `variant`/`range` spans, below.

This sidesteps the two problems a `fork()`-and-share-the-RNG design has: two copies of the `CaseRng`
would draw at the same cursor, and the child's trace/spans would have to be shipped back and
re-absorbed into the parent's `CaseRng`. `fork()` without `exec` is still attractive later for its
cost (**measured:** `fork`+`_exit`+`wait` is 186 µs at 4 MB RSS, 1.5 ms at 64 MB, 5.3 ms at
512 MB vs. ~1 ms for `exec` of a small Rust binary) and because sancov counters are at known
addresses; it would use the vDSO-patch path since there is no exec stop.

### 5.2 Harness shape

```rust
use dowsing::{curious, cautious, sandbox::{Sandbox, SandboxCoverage, VirtualTime, Outcome}};

let coverage = SandboxCoverage::new();
let sandbox = Sandbox::new("target/debug/examples/backoff_target")
    .virtual_time(VirtualTime::default())   // read_quantum, max jumps, realtime steps on/off
    .coverage(&coverage);

for mut rng in curious().with_coverage(coverage.clone()).take(DISCOVERY_CASES) {
    let outcome = sandbox.run(&mut rng).expect("spawn");   // draws from rng while the target runs
    if let Outcome::Panicked { .. } | Outcome::Hang = outcome {
        let case = rng.fork_case();
        let _ = rng.coverage();
        for mut variant in cautious().with_coverage(coverage.clone()).with_case(case).take(MINIMIZATION_CASES) {
            match sandbox.run(&mut variant).expect("spawn") {
                Outcome::Panicked { .. } | Outcome::Hang => { let _ = variant.coverage_with_cost(outcome_cost); }
                _ => variant.discard(),
            }
        }
    }
}
```

`Sandbox::run(&mut CaseRng<C>)` is generic over `C: CoverageCapture`; `SandboxCoverage` is the
adapter from §3.7. `Outcome` carries exit status / signal, the virtual elapsed time, the number of
scheduling points, stderr, and the *event log* (sequence of `(tid, syscall, decision)`) whose hash
is what the determinism test compares between a run and its replay.

### 5.3 Which decisions are `range`/`variant` spans (so `cautious()` can shrink them)

The reducer (`src/iter/shrink.rs`) shrinks `Variant`/`Length` spans towards **0** (`SetWord`
towards smaller words, `ZeroRange`), deletes `Item` spans of a `range`, and shortens the `range`
length. So every knob must be encoded so that **0 = "the boring, natural choice"** and the
sequence of scheduling decisions is a `range` whose items can be deleted:

```rust
// once per run
let quantum      = rng.variant(4);                 // 0: 1µs, 1: 100µs, 2: 10ms, 3: 1s per clock read
let realtime_mode = rng.variant(3);                // 0: realtime = base + vnow, 1: one backwards step, 2: one forwards step
// scheduling decisions, drawn lazily at each quiescent point from a pre-sized range
let mut jumps = rng.range(0..=MAX_JUMPS);          // Length span: cautious() shortens it
// per quiescent point, from jumps.next() (Item span: cautious() deletes it)
//   item.variant(4)   0: jump to d₁ (natural)   1: jump to d₂   2: overshoot d₁ by `mag`   3: jump past *all* deadlines
//   item.variant(6)   `mag` bucket: 0: 0, 1: 1ms, 2: 100ms, 3: 10s, 4: 10min, 5: 1h   (only used by 2)
```

When the `range` is exhausted the supervisor uses decision 0 ("natural") for the rest of the run,
so a shrunk case is literally "`n` natural advances, then one overshoot of 10 min, then natural"
and its prefix is a handful of non-zero bytes. `getrandom` payloads are plain `fill_bytes` draws
and shrink through the generic byte passes (`BlockZero`, `ByteLower`) — the demo's "flaky server"
failure pattern is derived from them, so shrinking also minimises the number of failures needed.

Domain cost for `cautious()`: `coverage_with_cost(jumps_taken * 1000 + non_natural_jumps * 10_000
+ virtual_elapsed_secs)` so the minimiser prefers fewer, more natural jumps and a shorter virtual
timeline before it falls back to fewer coverage features.

Nothing about the `curious`/`cautious` engines changes; the only additions are the `sandbox` module,
`SandboxCoverage`, and the announce hook in `src/sancov.rs`.

## 6. Risks and unknowns

* **Multi-threaded determinism is only as good as the scheduler.** Parking makes "all supervised
  waits blocked" exact, but two *runnable* threads still race in the kernel between our stops. The
  design leaves the resume-order hook to the scheduling spike; until then multi-threaded replays may
  diverge, and `Outcome::Nondeterministic` (event-log hash mismatch on replay) must be surfaced, not
  hidden. Demo stays single-threaded / `current_thread`.
* **Externally blocked threads** (`read`, `accept`, `waitpid`) are invisible to quiescence
  detection in this spike; a target that mixes real I/O with timers can see a jump while a read is in
  flight. Fixed by the network/files spike; documented limitation here.
* **Trap cost** (~10 µs; ~200× native for clock reads). Fine for the demo; the shared-page vDSO patch
  (§3.6) is designed but unverified end-to-end (injecting `mmap` into the tracee is standard
  rr/gVisor practice but was not exercised here).
* **`MAX_PREFIX_LEN = 4096` bytes.** Every decision costs 4 bytes (`variant` uses `next_u32`), so a
  run gets at most ~1000 recorded decisions before spans stop being recorded. `MAX_JUMPS` should
  default to ~200 and the harness should surface when a run exhausts it.
* **Scratch memory for zero `timespec`s.** The prototype will use the 128-byte x86-64 red zone below
  `rsp` at a syscall stop (the syscall wrapper cannot be using it) — a known hack; the proper fix is
  an injected scratch page (same mechanism as §3.6).
* **`vnow` epoch and `Instant` arithmetic.** Starting the virtual monotonic clock at 0 makes
  `Instant::now() - Duration` panic in the target; start at a large constant. Realtime steps
  backwards are a *feature* but must be opt-in per run (§5.3) so `curious()` does not spend its
  budget on them.
* **x86-64 only.** Register names, the `nr = -1` skip, and `rip -= 2` restart are x86-64 specifics;
  aarch64 needs `PTRACE_SET_SYSCALL`/`NT_ARM_SYSTEM_CALL`. Non-`AUDIT_ARCH_X86_64` syscalls are
  killed by the filter.
* **Environment.** Needs `ptrace_scope ≤ 1` (we are the parent) and a container seccomp profile that
  allows `ptrace`/`seccomp` (Docker's default does since 19.03). Only one tracer per process: you
  cannot `gdb` a target under the sandbox — replay-to-a-specific-decision plus `SIGSTOP` and
  `gdb -p` after detaching is the eventual answer.
* **Signals during emulated sleeps.** Since sleeps never enter the kernel, `EINTR`/`restart_syscall`
  semantics disappear; a target relying on `SIGALRM` interrupting `nanosleep` will behave
  differently. `setitimer`/`timer_create`/`alarm` are not emulated in this spike (nothing in
  std/tokio uses them).
* **Comparison feedback** (`trace-compares`) is lost across the process boundary until the shared
  page exists; edge coverage alone drives `curious()` in the prototype.
* **Unverified inferences** (flagged above): Go's vDSO fallback; injected-syscall page mapping;
  the exact `rip -= 2` restart in the presence of `TRACESYSGOOD` stops (well-trodden in rr/strace,
  not run here).

## 7. Prototype plan

Everything lives in the existing crate behind a `sandbox` cargo feature (Linux x86-64 only), plus
two examples. New dependency: `libc` (for `ptrace`, `seccomp`, `pidfd_*`, `user_regs_struct`);
`tokio` as a dev-dependency for the second target only.

### Files

| Path | Contents |
| --- | --- |
| `src/sandbox/mod.rs` | `Sandbox` builder, `run`, `Outcome`, `VirtualTime` options, event log |
| `src/sandbox/ptrace.rs` | thin safe wrappers: fork/traceme/exec, `waitpid(__WALL)`, `GETREGS`/`SETREGS`, `/proc/pid/mem` reader, exec-stop auxv walk |
| `src/sandbox/seccomp.rs` | BPF program builder (`RET_TRACE` set, `RET_ALLOW` default, arch check), reserved "announce" syscall range |
| `src/sandbox/clock.rs` | `VirtualClock { vnow, realtime_base, quantum }`, `clockid → ns`, timespec/timeval codecs |
| `src/sandbox/waits.rs` | per-syscall translate/probe/park logic, `Parked` table, futex wake matching, `pidfd_getfd` fd mirroring, timer queue, quiescence + jump decision |
| `src/sandbox/coverage.rs` | `SandboxCoverage: CoverageCapture`, counter-range extraction at exit, hit-count bucketing shared with `sancov.rs` |
| `src/sancov.rs` | + announce hook in `__sanitizer_cov_8bit_counters_init` when `DOWSING_SANDBOX=1` |
| `examples/backoff_target.rs` | the demo target (std only, no dowsing API) |
| `examples/backoff_tokio_target.rs` | same bug on tokio `current_thread` timers |
| `examples/backoff_sandbox.rs` | harness: `curious()` → `cautious()` → replay check, prints measurements |
| `src/tests/sandbox.rs` | determinism test (run twice, compare event-log hash), probe-mode tests against a tiny C-free Rust target |
| `spikes/virtual-time/RESULTS.md` | measurements from §7.3 |

### Demo target: `backoff_target`

A retry loop with exponential backoff, jitter and an overall deadline, written the way people
actually write it:

```rust
let deadline = Instant::now() + Duration::from_secs(120);
let mut rng = rand::rng();                       // seeded via getrandom → answered by the fuzzer
let mut backoff = Duration::from_millis(500);
for attempt in 1.. {
    if Instant::now() >= deadline { return Err(Timeout) }             // looks safe…
    match flaky_request(&mut rng, attempt) {                          // fails with p≈0.7 (from rng)
        Ok(v) => return Ok(v),
        Err(Transient) => {
            let jitter = Duration::from_millis(rng.random_range(0..backoff.as_millis() as u64));
            thread::sleep(backoff + jitter);                          // …but sleep can overshoot
            let remaining = deadline - Instant::now();                // BUG: panics once we are past the deadline
            backoff = (backoff * 2).min(Duration::from_secs(30)).min(remaining);
        }
    }
}
```

The panic needs (a) enough consecutive transient failures to get within one backoff of the 120 s
deadline (~minutes of wall-clock in real life) and (b) a sleep that overshoots the deadline. Under
the sandbox (a) is free (sleeps are jumps) and (b) is a `variant == 2` decision with a magnitude
bucket. `cautious()` should shrink to: minimal failure pattern, all jumps natural except one
overshoot. The tokio variant uses `tokio::time::sleep` and `tokio::time::timeout(remaining, …)` with
the same bug and exercises the `epoll_wait` probe path.

### Steps (each ends with a runnable check)

1. **Spawn + filter + auxv hide.** `Sandbox::run` executes a target, hides the vDSO, passes all
   time syscalls through untouched, reports exit status. Check: `strace`-free confirmation that
   `Instant::now()` now stops in the supervisor (stop counter).
2. **Clock emulation.** `clock_gettime`/`gettimeofday`/`time` + quantum. Check: probe target
   reports frozen/quantised time; `SystemTime` = base + vnow.
3. **Sleeps and futex timeouts, single thread.** Emulate `nanosleep`/`clock_nanosleep`; probe +
   park `futex` waits; natural advance only. Check: `thread::sleep(50ms)`, `park_timeout`,
   `Condvar::wait_timeout`, `recv_timeout` each finish with virtual elapsed = requested, wall < 5 ms.
4. **epoll/poll/select probes + fd mirroring.** Check: tokio `current_thread` sleep/timeout demo
   reports exact virtual elapsed; an `epoll_wait` that is woken by a pipe write from another thread
   completes without a jump.
5. **Coverage.** Announce hook + counter extraction at `exit_group`/fatal signal; `SandboxCoverage`.
   Check: `curious()` over the demo target accumulates coverage ids; `NoCoverage` control does not.
6. **Decisions from the `CaseRng`.** `getrandom` → `fill_bytes`; per-run `variant`s; jump `range`.
   Check: determinism test — replaying `fork_case()` yields an identical event-log hash and outcome
   over 100 cases.
7. **Demo end to end.** `backoff_sandbox` finds the panic with `curious()`, shrinks it with
   `cautious()`, replays the shrunk case, prints the measurements below. Same for the tokio target.
8. **Optional / stretch.** `timerfd` emulation; multi-thread tokio target (expect and report
   nondeterminism); shared-page vDSO fast path with the 1 M-`Instant::now()` probe as the benchmark.

### What will be measured (into `RESULTS.md`)

* Wall time to first failure and number of runs, `curious()` vs. a `NoCoverage` control, for both
  targets; the virtual time of the failing run (expected ≥ 120 s) vs. wall time (expected ≤ 10 ms
  per run).
* Replay fidelity: 100 replays of the failing case, identical outcome and event-log hash.
* Shrink quality: bytes consumed, non-zero bytes, number of jumps and of non-natural jumps in the
  `cautious()` result; time to shrink.
* Overhead: stops per run, µs per stop by kind (clock read, sleep, probe), `exec`+`waitpid` cost
  for the target, total per-run wall time.
* Regression: `cargo test` and `cargo clippy --all-targets` stay green with and without the
  `sandbox` feature (54 tests pass on the base branch today).

## Appendix: experiments run for this memo

All throwaway code was kept out of the repository; the parts worth re-running are summarised here.

**A. Syscall census** — `strace -f -e trace=clock_gettime,clock_nanosleep,nanosleep,futex,epoll_wait,…`
on a Rust probe with modes `instant` (1 M `Instant::now()`), `sleep`, `park`, `condvar`, `recv`, and
on a tokio program (`current_thread` and `multi_thread`) doing `sleep(30ms)` then
`timeout(20ms, pending())`. Results in §2.

**B. ptrace + seccomp supervisor (~200 lines of C).** Child: `PTRACE_TRACEME`, `no_new_privs`,
seccomp filter returning `RET_TRACE` for 15 time-related syscall numbers, `raise(SIGSTOP)`,
`execvp`. Parent: options `TRACESECCOMP|TRACEEXEC|TRACECLONE|EXITKILL|TRACESYSGOOD`; at
`PTRACE_EVENT_EXEC` reopen `/proc/pid/mem`, walk the stack to auxv, set `AT_SYSINFO_EHDR → AT_IGNORE`
(or, with `--patch-vdso`, overwrite `__vdso_clock_gettime`/`__vdso_gettimeofday`/`__vdso_time` with
`b8 NN 00 00 00 0f 05 c3`); at `PTRACE_EVENT_SECCOMP` emulate `clock_gettime`/`gettimeofday`/`time`
(write result, `orig_rax = -1`, `rax = 0`, `PTRACE_CONT`), `nanosleep`/`clock_nanosleep` (advance
`vnow`, skip), `futex` wait with timeout (single-threaded shortcut: advance to deadline, return
`-ETIMEDOUT`), `epoll_wait(ms>0)` (set `r10 = 0`, `PTRACE_SYSCALL`, at exit if `rax == 0` advance by
`ms`).

Measured on the probes:

| Run | stops | emulated | virtual | wall | µs/stop |
| --- | --- | --- | --- | --- | --- |
| `instant`, vDSO kept (control) | 2 | 0 | — | 0.064 s | — (51 ns per `Instant::now()`) |
| `instant`, vDSO hidden, passthrough (`CONT` only) | 2 000 005 | 0 | 0 | 15.55 s | 7.78 |
| `instant`, vDSO hidden, emulated | 2 000 005 | 2 000 003 | 0 (`1M Instant::now in 0ns`) | 20.24 s | 10.12 |
| `sleep` 50 ms | 3 | 1 | 0.050 s | 0.001 s | — |
| `park` / `condvar` / `recv` 50 ms | 4 / 4 / 9 | 2 / 2 / 7 | 0.050 s | 0.001 s | — |
| tokio `current_thread` (30 ms + 20 ms) | 34 | 23 | 0.050 s (`elapsed 50ms`) | 0.002 s | — |
| tokio `multi_thread` | 63 | 27 | 0.050 s | 0.002 s | — |
| musl static-pie `sleep` / `park` | 3 / 4 | 1 / 2 | 0.050 s | < 0.001 s | — |
| `--patch-vdso` (auxv intact) `sleep` / tokio | 3 / 34 | 1 / 23 | 0.050 s | 0.001 s | — |

**C. Misc checks (~100 lines of C):** `SECCOMP_RET_USER_NOTIF` with `SECCOMP_FILTER_FLAG_NEW_LISTENER`
works unprivileged (supervisor received `nr=110` and injected `4242`); `pidfd_open` +
`pidfd_getfd` on a child's epoll fd works and `epoll_wait` on the duplicate observes the child's
`eventfd` write; `fork`+`_exit`+`waitpid` costs 186 µs / 1.5 ms / 5.3 ms at 4 / 64 / 512 MB RSS;
`unshare -Ur --time` is permitted (`apparmor_restrict_unprivileged_userns = 0`).
