# fs-env-intercept: files, environment, entropy and identity served by the fuzzer

A standalone prototype (not a member of the root workspace) that runs an **unmodified** target
inside a seccomp user-notification sandbox so its config files, directories, symlinks,
`/dev/urandom`, `getrandom`, `getpid`/`gettid`/`uname`/`sysinfo` and environment variables are
answered from a dowsing `CaseRng` instead of being mocked. `curious()` finds an injected bug through
those inputs, the case replays byte-for-byte, and `cautious()` minimizes the config file to 12 bytes.

The design memo with the alternatives that were rejected and why is [`DESIGN.md`](DESIGN.md);
§10 there records what the prototype changed relative to the plan.

## Approach

```
 fuzz thread (seccomp filter installed, permanent)        supervisor thread (unfiltered, same process)
 ┌──────────────────────────────────────────┐             ┌──────────────────────────────────────────┐
 │ harness: rng = curious().next()          │  CaseRng    │ epoll { listener }                       │
 │ sandbox.run_case(rng, &spec, || target())│ ──────────▶ │ RECV notification                        │
 │   target: open("/etc/app/app.conf")  ────┼─ trap ─────▶│   real path?     -> FLAG_CONTINUE        │
 │           read(fd) / fstat / mmap ...    │  native     │   virtual path?  -> materialize from rng │
 │           read(urandom fd) ──────────────┼─ trap ─────▶│                     into tmpfs, ADDFD    │
 │           getrandom / getpid / uname ────┼─ trap ─────▶│   entropy/identity -> draw, write target │
 │ (rng, report, result) ◀──────────────────┼─────────────│ SEND answer                              │
 └──────────────────────────────────────────┘             └──────────────────────────────────────────┘
```

* **Interception primitive:** `SECCOMP_RET_USER_NOTIF` with a thread-scoped classic-BPF filter
  (`src/bpf.rs`, raw `libc`, no `nix`/`seccompiler`). Only path-based syscalls (`open`, `openat`,
  `openat2`, `stat`, `lstat`, `newfstatat`, `statx`, `readlink(at)`, `access`, `faccessat(2)`),
  `getrandom`, `getpid`/`gettid`/`uname`/`sysinfo`, and `read`/`pread64`/`readv`/`preadv(2)` **only
  when `args[0]` is inside the sandbox's injected urandom fd window** (`fd 1000 + 8*k .. +8`) are
  trapped. Everything else (`read` on ordinary fds, `mmap`, `futex`, `write`, ...) runs at native
  speed. ptrace was rejected because a thread cannot trace a sibling in its own process and costs
  two stops per syscall (DESIGN.md §2.3, §4).
* **Supervisor** (`src/supervisor.rs`): one epoll loop per `Sandbox` over the listener fd. `POLLHUP`
  is the "all filtered tasks exited" signal (a blocking `RECV` after target exit hangs forever —
  reproduced in the memo). Every notification is attributed to its `tid`, and `dispatch` is a flat
  `match` on the syscall number: the network/time/scheduler spikes add their fds to the same epoll
  set and their syscall numbers to the same `match`, holding a notification instead of answering it
  when they want to park the calling thread.
* **Files** (`src/vfs.rs`, `src/fs.rs`): the harness declares a virtual tree (`Spec::file/dir/
  symlink`). Nothing is created until the target touches a virtual path; then the node is
  materialized once per case into `$XDG_RUNTIME_DIR/dowsing/<pid>/<case>/` (falls back to
  `/dev/shm`) and the fd is injected atomically with `SECCOMP_IOCTL_NOTIF_ADDFD | SETFD | SEND`, so
  `read`/`fstat`/`mmap`/`getdents64` are done by the kernel. Real paths get `FLAG_CONTINUE`.
  `statx`/`newfstatat`/`readlink` on virtual paths are served by copying the result into target
  memory with `process_vm_writev` (`src/mem.rs`), after `ID_VALID` confirms the target is still
  blocked in that syscall. Per-case trees are deleted by an unfiltered janitor thread.
* **Entropy** (`src/entropy.rs`): `open("/dev/urandom")` injects a real urandom fd at a fixed slot
  so the BPF filter can recognise reads on it; reads and `getrandom` draw `variant(full | short |
  EINTR/EAGAIN)` then `fill_bytes`. Draws are capped at 64 bytes per call and expanded
  deterministically beyond that so a `read(1 MiB)` does not blow the trace budget.
* **Identity** (`src/identity.rs`): pid/tid/uname/sysinfo are `variant`s over small "interesting"
  sets (index 0 = realistic value), cached for the case so repeated calls agree.
* **Environment** (`src/env.rs`): `std::env::var` makes no syscall, so declared variables are
  applied with `std::env::set_var`/`remove_var` at case start (restored at case end) and a virtual
  `/proc/self/environ` reflecting them is served for programs that read it.
* **Structured draws** (`src/draw.rs`): every decision is a `variant` or a `range` on the
  `CaseRng` (`Draw::variant/bytes/sequence/fill`), so `cautious()` shrinks *choices* (delete a
  config line, pick default env, zero entropy), not opaque bytes. `Draw::sequence` gives
  line-structured files whose lines are deletable as units.
* **Cost / discard:** `CaseCost = materialized bytes + non-zero entropy bytes + 16 × non-default
  variants`; a case is discarded when it exceeds the trace budget or an unsupported syscall shape
  had to be answered `ENOSYS` (e.g. `openat2` on a virtual path). Opening a virtual path for
  writing is answered `EROFS` (read-only tree; not a discard).
* **CPU pinning (new finding, on by default):** a notification round trip is a thread ping-pong.
  With fuzz thread and supervisor on different CPUs it costs ~12 µs (IPI + wakeup); pinned to the
  same CPU it is a context switch, ~2.4 µs. `Sandbox::install()` pins both threads to the CPU the
  fuzz thread is on; `Sandbox::install_with(Options { pin: false, .. })` or `--no-pin` opts out.

Dependencies: `iterator-fuzz` (path `../..`), `libc`, `rand` (for `SmallRng` in the deterministic
entropy expansion). No `nix`, `rayon` or anything else. The root `Cargo.toml` and `src/` are
untouched.

## Build and run (fresh clone, Linux x86_64, stable Rust 1.98)

```bash
git clone https://github.com/DioxusLabs/dowsing.git
cd dowsing
git checkout devin/spike/fs-env-intercept
cd spikes/fs-env-intercept

# 1. unit/integration tests (seccomp unotify, virtual fs, entropy, replay, minimization)
cargo test --release

# 2. the demo with SanitizerCoverage feedback (the harness itself is instrumented; the sandbox
#    lives in this crate's lib and stays outside the instrumented code)
cargo rustc --release --example sandboxed_config -- \
  -Cpasses=sancov-module \
  -Cllvm-args=-sanitizer-coverage-level=3 \
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
  -Cllvm-args=-sanitizer-coverage-pc-table \
  -Cllvm-args=-sanitizer-coverage-trace-compares
target/release/examples/sandboxed_config          # find, replay x3, minimize, write target/dowsing-repro/app.conf
target/release/examples/sandboxed_config --no-pin # same without CPU pinning
target/release/examples/sandboxed_config --raw    # app.conf as flat random bytes (does NOT find the bug, see below)
scripts/time_to_bug.sh 10                         # cases-to-bug over 10 seeds (add --no-dict / --raw)

# 3. latency and throughput tables (no instrumentation needed)
cargo run --release --example latency
cargo run --release --example latency -- --no-pin

# lint
cargo clippy --all-targets
```

Kernel requirements (verified only on 6.8 here): `seccomp(SECCOMP_FILTER_FLAG_NEW_LISTENER)`,
`SECCOMP_USER_NOTIF_FLAG_CONTINUE`, `SECCOMP_IOCTL_NOTIF_ADDFD` with `SECCOMP_ADDFD_FLAG_SEND`
(the newest of these, I believe 5.14+), `process_vm_readv/writev`. No privileges, no ptrace, no
user namespaces. `Sandbox::install()` returns the `seccomp(2)` errno if an outer sandbox (e.g. a
container seccomp profile) forbids installing filters.

## The demo

`examples/demo_target/mod.rs` is the application. It knows nothing about dowsing: it reads
`APP_MODE`, parses `/etc/app/app.conf` (`mode`, `retries`, `name`, `seed`), reads 8 bytes from
`/dev/urandom`, calls `getrandom(16)`, lists `/var/lib/app`, and reports `getpid()` and
`uname().release`. Injected bug: with `mode=strict` in the **file** *and* `APP_MODE=strict` in the
**environment** *and* `retries as u8 == nonce[0]` (first urandom byte), a table index wraps and the
target panics with `index out of bounds`.

`examples/demo_target/harness.rs` declares what is virtual:

```rust
Spec::new()
    .file("/etc/app/app.conf", Content::Generate(Arc::new(structured_config))) // key=value lines via Draw::sequence
    .file("/var/lib/app/state.db", Content::Random { max_len: 16 })
    .dir("/var/lib/app", 2)                                                     // + up to 2 random entries
    .env("APP_MODE", vec![Some("lenient"), Some("strict"), None])              // index 0 = default, so "strict" must be *found*
```

`examples/sandboxed_config.rs` runs `curious()` until the panic, replays the found `Case` three
times asserting identical failure, identical materialized files and identical entropy, then runs
`cautious()` for 3 000 cases and prints the smallest reproducer. Output on this box (seed 1):

```
found bug after 5078 cases (0 discarded) in 1.15s (4420 cases/s): PANIC: index out of bounds: the len is 256 but the index is 256
  /etc/app/app.conf: "mode=\nmode=\nmode=strict\n# note\n"
  /var/lib/app/a: "�\0�\u{18}"
  /var/lib/app/state.db: "\0\0R��V�<��"
  entropy served: [3, 0, 0, 0, 0, 0, 0, 0, 126, 60, 249, 113, 35, 100, 213, 84, 56, 61, 230, 177, 65, 80, 116, 61]
replayed 3x: identical failure, files and entropy
minimized in 3000 cases / 386.67ms: app.conf = "mode=strict\n" (12 bytes), env = [("APP_MODE", Some("strict"))],
  entropy = [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], cost = 13, features = 386,
  consumed = 64 bytes, SEND retries = 0
wrote target/dowsing-repro/app.conf
```

The minimized reproducer is smaller than the memo predicted (`mode=strict\nretries=1\n`, 22 bytes):
`retries` defaults to 3, so `cautious()` dropped the `retries=` line and kept `nonce[0] == 3`
instead; all other entropy bytes are zero because non-zero entropy bytes are part of `CaseCost`.
`tests/replay.rs` pins the memo's version too (`retries=0` in the file, all-zero entropy, ≤ 32
bytes) and checks byte-for-byte replay of files, env and entropy.

## Measurements (this box: Xeon Platinum 8559C, 8 vCPU, Ubuntu kernel 6.8.0-1061-aws, rustc 1.98.1, single runs, ±20 %)

### Per-syscall latency through the real Rust path (`cargo run --release --example latency`)

| operation | native | sandboxed, pinned (default) | sandboxed, `--no-pin` | memo's C number |
|---|---:|---:|---:|---:|
| `getpid` (trapped, answered) | 0.10 µs | **2.44 µs** | 12.04 µs | 8.36 µs |
| `open+close` real file (`FLAG_CONTINUE` passthrough) | 0.98 µs | **4.37 µs** | 14.52 µs | 9.55 µs |
| `getrandom(16)` (trapped, drawn) | 0.29 µs | **3.10 µs** | 10.14 µs | – |
| `open+read(8)+close /dev/urandom` (2 traps) | 1.24 µs | **7.62 µs** | 22.08 µs | – |
| read virtual `/etc/app/app.conf` (trap + `ADDFD`, native read) | – | **8.49 µs** | 25.52 µs | 13.90 µs (memfd) |
| 100 × `open+close` real file per case (R1 passthrough tax) | 91 µs | **431 µs** | 1313 µs | – |

Same-CPU pinning of the fuzz/supervisor pair is the single biggest lever found: the memo's C
numbers were taken unpinned on the same box, and the Rust path unpinned is ~1.4× slower than C
(epoll + mutex + `ID_VALID`); pinned it is 3.4× faster than the C baseline.

### Per-case throughput (`NoCoverage`, uninstrumented, from the same run)

| target | pinned | `--no-pin` |
|---|---:|---:|
| empty target (`start_case` + `finish_case` only) | 94 394 cases/s | 35 473 cases/s |
| one virtual file (materialize + open + read) | 25 987 cases/s | 14 791 cases/s |
| demo target (conf, urandom, getrandom, dir listing, pid, uname) | **17 123 cases/s** | 7 388 cases/s |
| 100 real opens per case | 2 147 cases/s | 763 cases/s |

### End-to-end with SanitizerCoverage + cmp dictionary (`sandboxed_config`)

* discovery: 4 420 cases/s pinned vs 2 812 cases/s unpinned (seed 1: 5 078 cases, 1.15 s vs 1.81 s);
  minimization 3 000 cases in 387 ms vs 794 ms.
* time-to-bug over 10 seeds (`scripts/time_to_bug.sh 10`), 200 000-case budget:

| configuration | min | median | max | found | throughput |
|---|---:|---:|---:|---:|---:|
| structured `app.conf`, cmp dictionary on (default) | 5 078 | 14 325 | 35 156 | 10/10 | ~3.8k cases/s |
| structured `app.conf`, `--no-dict` | 1 101 | 32 576 | >200 000 | 9/10 | ~9k cases/s |
| `--raw` flat random bytes (`Content::Random { max_len: 48 }`), dict on | – | – | – | **0/5** | ~4.1k cases/s |

The dictionary halves the median case count and removes the misses, at ~2.4× lower throughput
(the cmp hooks are the cost); wall-clock medians are close (~3.5 s vs ~3.6 s).

* replay determinism: 3/3 identical (failure message, materialized file bytes, entropy) in the
  demo; `tests/replay.rs` and `tests/smoke.rs` assert the same for two independent runs of a
  `Case` including the served pid/uname.
* `SEND → ENOENT` retries observed (R5): 0 in every run.
* minimized `app.conf`: 12 bytes (`mode=strict\n`), `CaseCost` 13, 64 trace bytes consumed.

## What works

* Thread-scoped seccomp filter + in-process unfiltered supervisor, unprivileged, no ptrace.
* Virtual files, directories (`read_dir`/`getdents64` served natively from the materialized tree,
  with fuzzer-chosen extra entries), symlinks (fuzzer-chosen target), `ENOENT`/`EACCES` outcomes as
  variants, `statx`/`newfstatat`/`stat`/`lstat`/`readlink`/`access` copy-out. `openat2` on a
  real path passes through; on a virtual path it is `ENOSYS` + discard (unsupported, counted).
* Real paths untouched (`FLAG_CONTINUE`), including everything the Rust runtime and the harness
  do on the fuzz thread. Threads spawned by the target inherit the filter (and the CPU pin) and
  are attributed per tid; they read the same virtual tree (`tests/smoke.rs`).
* `/dev/urandom` and `/dev/random` (fixed injected fd window per sandbox, several sandboxes per
  process), `getrandom`, short-read/`EINTR`/`EAGAIN` faults as variants, `readv`/`preadv` forms.
* `getpid`/`gettid`/`uname`/`sysinfo` from interesting sets, stable within a case.
* Environment variables (variant sets incl. unset) + virtual `/proc/self/environ` and
  `/proc/<pid>/environ`.
* Deterministic replay (`Case::replay`), `cautious()` minimization through the public
  `variant`/`range` API only — no new shrink passes in the root crate.
* Panics in the target propagate through `run_case` after the sandbox state is restored; the
  janitor deletes per-case tmpfs trees off the fuzz thread.

## What does not work / limitations

* **Flat random-bytes config (`--raw`) never finds the bug** within 200 000 cases (0/5 seeds). Rust
  string comparisons compile to a length check plus `bcmp`; SanitizerCoverage `trace-compares` only
  hooks integer `cmp` instructions, and dowsing's `src/sancov.rs` has no
  `__sanitizer_weak_hook_memcmp/strcmp` hooks, so the dictionary never learns `"mode"`/`"strict"`.
  This is a root-crate feature gap, not a sandbox one; the structured `Draw::sequence` generator is
  the workaround and also what makes the minimized file readable.
* **`Isolation::Fork` (memo step 7) is not implemented.** `process::exit`/`abort`/segfault in the
  target still kills the fuzzer; `TargetMem` is already pid-parameterized and `pidfd_getfd` /
  `process_vm_*` were verified in the memo, but the shared-memory sancov counter map needs a hook
  in the root crate, so it was left for the next session as planned.
* Multithreaded targets: draw order is syscall-arrival order, so a racy target replays
  non-deterministically until the scheduler spike lands (R2). Attribution per tid already exists.
* Opening a virtual path for writing/creating (`O_WRONLY`/`O_RDWR`/`O_CREAT`/`O_TMPFILE`) returns
  `EROFS`. Syscalls that are not trapped at all (`rename`, `unlink`, `mkdir`, `*xattr`, `inotify`,
  `chdir`, `execve`) hit the real filesystem, where virtual paths do not exist (`ENOENT`).
* `std::env::set_var` in thread mode is process-global: any other thread reading the environment
  during a case sees the fuzzed values (a fork-mode `setenv` in the child avoids this).
* vDSO `getrandom` (kernel ≥ 6.11 with glibc ≥ 2.41) would bypass the filter (R7). Not on this box.
* The passthrough tax is real: 100 real opens/case costs 4.4 µs each even pinned (R1).
* The seccomp filter, `NO_NEW_PRIVS` and the CPU pin are permanent for the fuzz thread and inherited
  by anything it spawns; `Sandbox` must therefore be created once per worker thread, not per case.
* Numbers are single runs on one idle VM.

## Next steps

1. **Fork isolation:** `Sandbox::run_forked` — fork per case, child installs the filter and hands
   the listener over `SCM_RIGHTS` (or `pidfd_getfd`), `TargetMem::new(child_pid)`, `setenv` in the
   child, exit status → outcome. Needs the sancov counter region mapped `MAP_SHARED` before the
   fork (a small `CoverageCapture` hook in the root crate) — measure cases/s vs RSS against the
   memo's fork curve.
2. **memcmp/strcmp dictionary hooks** in `src/sancov.rs` (`__sanitizer_weak_hook_memcmp` etc.) so
   `--raw` byte-string configs become findable.
3. **Scheduler/network/time modules** on the same loop: park notifications (`Pending`), add
   sockets/timerfds to the epoll set, choose the thread to resume with a `variant`.
4. **Level-2 fault injection:** optional trapping of `read`/`write` on virtual fds for short reads
   and `EIO`, and `mmap(MAP_SHARED)` write-back.
5. Pin one fuzz/supervisor pair per CPU in `ParallelCases`; measure scaling across 8 vCPUs.
6. Allow-list address ranges of `.rodata` path literals in the BPF program to cut the passthrough
   tax for known-real paths (R1).
