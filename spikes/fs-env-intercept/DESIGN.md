# Spike `fs-env-intercept`: filesystem, environment, and entropy interception

Status: design memo, no prototype yet.
Scope: local Linux x86_64 only. No cloud, no distributed execution, no full-VM/KVM snapshots.

## 0. TL;DR

Recommendation: **seccomp user-space notification (`SECCOMP_RET_USER_NOTIF`) with a thread-scoped
filter installed on the fuzz thread, served by an unfiltered supervisor thread in the same
process**, with the exact same supervisor code reusable for a fork-per-case child process (listener
grabbed with `pidfd_getfd`, target memory via `process_vm_readv/writev`). Trap only what must be
virtual:

* path-based syscalls (`openat`, `statx`/`newfstatat`, `readlink(at)`, `access`/`faccessat2`,
  directory `openat(O_DIRECTORY)`) — the supervisor compares the path against the harness's declared
  virtual tree; non-virtual paths get `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (kernel executes the real
  call, ~9.5 µs instead of ~0.8 µs), virtual paths are materialized on demand from the `CaseRng`
  into a per-case tmpfs directory and the resulting fd is *injected* with
  `SECCOMP_IOCTL_NOTIF_ADDFD|SETFD|SEND`. After that `read/pread/fstat/lseek/mmap/getdents64` on
  the injected fd are ordinary kernel syscalls at native speed — no trap, no emulation.
* `/dev/urandom` is injected at a fixed high fd (e.g. 1000). The BPF program traps
  `read/pread64/readv` **only when `args[0] == 1000`** (BPF can compare raw args), so every other
  read in the process stays native. Each trapped read draws `len` bytes from the `CaseRng`.
* `getrandom`, `getpid`, `gettid`, `uname`, `sysinfo` are always trapped and answered from the case.
* environment variables are not a syscall in Rust/glibc (`std::env::var` reads the `environ` block
  that `execve` wrote) — they are applied at *case start* (`setenv` in a freshly forked child, or a
  documented, unsafe `std::env::set_var` in thread mode) and a virtual `/proc/self/environ` is
  served from the same declared list for targets that read the file.

Measured on this box (details in §2): a trapped syscall round trip costs ~8 µs in-process and
~7.5–8 µs cross-process; `PTRACE_SYSCALL` costs ~16 µs (two stops); seccomp `RET_TRACE`+ptrace ~8.7
µs; `fork()+exit+wait` costs 0.3 ms at 10 MiB RSS, 2.3 ms at 100 MiB, 12 ms at 1 GiB, 41 ms at 4
GiB. A blocking `SECCOMP_IOCTL_NOTIF_RECV` **hangs forever if the target exits** (man page BUGS,
reproduced) — the loop must be `epoll`-driven, which is also exactly what is needed to share it with
network/time/scheduler interception (§5).

Everything the fuzzer chooses is a `variant` (which outcome) or a `range` (how many / which bytes)
on the `CaseRng`, so `cautious()` shrinks the file to a few bytes and the outcomes to the boring
ones without any new shrinker code (§6).

## 1. Problem restatement

dowsing already controls the *explicit* randomness a harness draws through the `CaseRng`. The
remaining nondeterministic inputs of a real target are implicit: files it opens, `/dev/urandom`,
`getrandom`, identity/system queries (`getpid`, `gettid`, `uname`, `sysinfo`), environment variables.
Today those need mocks or `#[cfg(test)]` seams. The goal of this spike is that the *unmodified*
target runs while the fuzzer answers those syscalls with bytes drawn from the same `CaseRng`, so

1. execution is deterministic given a `Case` (replay works),
2. coverage-guided search (`curious()`) can steer the *file contents* and *entropy* toward new
   coverage, and
3. `cautious()` can shrink the file/entropy/outcomes to a tiny reproducer.

Constraints from the vision: one local machine, unprivileged, the same supervisor loop must later
also serve networking, time, and deterministic scheduling, and must not preclude snapshot/rewind.

## 2. Measured facts (this machine)

Machine: Ubuntu, kernel `6.8.0-1061-aws`, Intel Xeon Platinum 8559C, 8 vCPUs, ~31 GiB RAM,
glibc 2.35, rustc 1.98.1, `kernel.yama.ptrace_scope=1`, `vm.unprivileged_userfaultfd=0`,
`kernel.unprivileged_userns_clone=1` (`unshare -Urm true` works), `CONFIG_SECCOMP_FILTER=y`,
no CRIU, `strace/gdb/perf` present. All experiments are throwaway C programs kept outside the repo
(`~/spike-exp/unotif_thread.c`, `unotif_multi.c`, `unotif_child.c`, `rs/t.rs`); numbers are single
runs of 20 000 iterations (fork: 100/20 iterations) on an otherwise idle box, so treat them as ±20 %.

### 2.1 seccomp user notification works unprivileged, thread-scoped, in-process

`unotif_thread.c`: the *fuzz thread* sets `PR_SET_NO_NEW_PRIVS` and installs a filter with
`SECCOMP_FILTER_FLAG_NEW_LISTENER`; the *main thread* (unfiltered, same process) serves the listener.

```
getpid() in target thread = 4242 (real 5395)        <- supervisor-supplied value
open(/virt/etc/app.conf) -> fd 4, read 26 bytes      <- virtual file from a memfd
fstat: size=26 mode=100777
open(/dev/urandom) -> fd 900, read 8: 01 02 03 04   <- fixed-fd urandom, reads trapped
getrandom -> 8: a0 a1 a2 ...
uname.sysname=Linux nodename=dowsing
passthrough open(/etc/hostname) -> fd 4 (errno 0)    <- FLAG_CONTINUE
main thread getpid() = 5408 (unfiltered: real pid)   <- filter really is per-thread
main: Seccomp: 0 / Seccomp_filters: 0
```

Costs (µs per call, 20 000 calls):

| path                                             | µs     |
|--------------------------------------------------|--------|
| native `gettid` (filter says ALLOW)              | 0.10   |
| unfiltered `open+close` baseline                 | 0.82   |
| trapped `getpid` (RECV → SEND, in-process)       | 8.36   |
| `open+close` answered with `FLAG_CONTINUE`       | 9.55   |
| `open+close` answered with a virtual memfd       | 13.90  |

`unotif_multi.c`: three filtered threads, each with its own listener, served concurrently; threads
spawned *from* a filtered thread inherit the filter and report through the same listener with
`req->pid` = the child's tid. This is what lets the supervisor attribute syscalls to threads later
(scheduler spike).

### 2.2 The same thing across a fork boundary

`unotif_child.c`: the child installs the filter, the parent grabs the listener with
`pidfd_open`+`pidfd_getfd` (requires `PTRACE_MODE_ATTACH_REALCREDS`, i.e. proves `ptrace_scope=1`
lets a parent supervise a child), opens `/proc/<pid>/mem` `O_RDWR`, reads the `openat` path both
via `process_vm_readv` and via `pread(/proc/pid/mem)`, injects a memfd at fd 900 with
`ADDFD|SETFD|SEND`:

```
parent: pidfd_getfd of child's listener OK (fd 8)
parent: open(/proc/6302/mem, O_RDWR) -> 9
parent: openat path via process_vm_readv(255)='/virt/config' via /proc/pid/mem(255)='/virt/config'
parent: ADDFD|SETFD|SEND -> 900
child: getpid()=777 open(/virt/config)=900 read=17 'hello from parent'
child: trapped getpid via child-process unotify: 7.55–8.21 us/call
parent: POLLHUP on listener (all filter users exited); revents=0x10
```

Two gotchas reproduced:

* A blocking `SECCOMP_IOCTL_NOTIF_RECV` issued after the target exited **blocks forever** (the man
  page lists this under BUGS). The first version of the experiment hung there. `poll()` on the
  listener returns `POLLHUP` after the last filtered task exits *and is reaped*, so the supervisor
  must be poll/epoll driven and must own reaping.
* `SECCOMP_IOCTL_NOTIF_RECV` on a non-listener fd returns `ENOTTY` — worth checking explicitly when
  the listener is transferred between processes.

### 2.3 ptrace alternatives, measured

Same box, `getpid` loop:

| mechanism                                                  | stops/call | µs/call |
|------------------------------------------------------------|-----------:|--------:|
| `PTRACE_SYSCALL` (entry + exit stop, `GETREGS` each)       | 2          | 16.09   |
| seccomp `RET_TRACE` + `PTRACE_EVENT_SECCOMP`, skip+rewrite | 1          | 8.71    |
| seccomp `USER_NOTIF`, in-process                           | 1          | 8.36    |
| seccomp `USER_NOTIF`, cross-process                        | 1          | 7.55    |

So the primitive choice is not about speed (rr's `RET_TRACE` trick and unotify are within noise of
each other); it is about *what the supervisor can do without stopping the whole task* (§3).

### 2.4 fork() cost vs RSS (snapshot-via-fork budget)

```
fork()+exit+wait at RSS    10 MiB: 0.32 ms (child touches 1% of pages: 0.42 ms)
fork()+exit+wait at RSS   100 MiB: 2.27 ms (child touches 1% of pages: 2.78 ms)
fork()+exit+wait at RSS  1024 MiB: 12.20 ms (child touches 1% of pages: 15.41 ms)
fork()+exit+wait at RSS  4096 MiB: 41.02 ms (child touches 1% of pages: 60.09 ms)
```

Roughly 10–12 ms per GiB of touched anonymous memory (page-table copy + CoW faults), i.e. a
fork-per-case model caps at ~3 000 cases/s for a 10 MiB harness and ~400/s at 100 MiB. This is why
the default should stay in-process (like dowsing today) with fork as an opt-in isolation/snapshot
mode.

### 2.5 What Rust std actually does (strace of `rs/t.rs`)

| std call                                   | syscalls seen                                                            |
|--------------------------------------------|--------------------------------------------------------------------------|
| `fs::read_to_string("/virt/etc/app.conf")` | `openat(AT_FDCWD, ..., O_RDONLY|O_CLOEXEC)` then `statx(fd,"",AT_EMPTY_PATH)`, `read` |
| `fs::metadata("/virt/etc")`                | `statx(AT_FDCWD, path, AT_STATX_SYNC_AS_STAT, STATX_ALL, ...)` (not `stat`/`newfstatat`) |
| `fs::read_dir("/virt/etc")`                | `openat(..., O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY)` then `getdents64(fd)` |
| `fs::read_link("/virt/link")`              | `readlink(path, buf, 256)`                                               |
| `File::open("/dev/urandom")` + `read_exact` | `openat` + `read(fd, buf, 16)`                                          |
| `HashMap::new()` (first per thread)        | `getrandom(buf, 16, GRND_INSECURE)`; process startup (before `main`) also does one `getrandom(8, GRND_NONBLOCK)` |
| `env::var`                                 | **no syscall** (reads `environ` set up by `execve`)                      |
| `process::id()`                            | `getpid`                                                                 |
| `thread::current().id()` / thread naming   | `gettid`                                                                 |
| `SystemTime::now`, `Instant::now`          | **no syscall** (`clock_gettime` via vDSO) — time spike must handle vDSO |
| `thread::available_parallelism`            | `sched_getaffinity`, opens `/proc/self/cgroup`, `/sys/fs/cgroup/...`     |

Consequences: the filter must trap `statx` (and `newfstatat` for C targets), `getdents64` is *not*
needed when the directory fd is a real injected fd, env vars cannot be intercepted at the syscall
layer at all in a running process, and ordinary programs open plenty of non-virtual `/proc` and
`/sys` files, so `CONTINUE` passthrough must be the cheap default.

### 2.6 Kernel/feature availability (6.8)

`SECCOMP_FILTER_FLAG_NEW_LISTENER` (5.0), `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (5.5),
`SECCOMP_IOCTL_NOTIF_ADDFD` + `SETFD` (5.9), `SECCOMP_ADDFD_FLAG_SEND` (5.14),
`SECCOMP_IOCTL_NOTIF_SET_FLAGS`/`WAIT_KILLABLE_RECV` (5.19), `pidfd_getfd` (5.6) — all present.
vDSO `getrandom` is 6.11+ so on this kernel `getrandom` is always a real syscall (see risk R7 for
newer kernels).

## 3. Recommended approach

### 3.1 Primitive: seccomp unotify, not ptrace

Both were measured within noise for the round trip (§2.3). unotify wins on everything else that
matters for *this* spike and the ones after it:

* **Selective and cheap.** The BPF program decides per syscall number *and raw argument values*
  what to trap. Everything else runs at native speed (`gettid` 0.10 µs). ptrace with
  `PTRACE_SYSCALL` stops every syscall twice; rr's `RET_TRACE` trick is equally selective but still
  needs a tracer, which brings the next point.
* **No tracer ownership.** A ptracer must be a single process/thread that is also the one that
  `waitpid`s the tracee, it conflicts with gdb/rr/`cargo test`'s own use of the process, and a
  thread cannot ptrace a sibling thread in its own process. unotify's listener is just an fd:
  any thread (or a forked parent) can serve it, several listeners can be multiplexed in one
  `epoll`, and it coexists with a debugger attached to the target.
* **Works in-process.** dowsing's current model runs the harness on the test thread and captures
  coverage in-process (`SancovCoverage`, `LlvmCoverage`). A thread-scoped filter on that thread
  plus a supervisor thread keeps that model; the supervisor can read/write the target's buffers
  with a plain pointer (same address space). ptrace cannot do this.
* **Transferable to a child.** The same listener can be grabbed by a forked parent
  (`pidfd_getfd`, verified). `process_vm_readv/writev` and `/proc/pid/mem` work there
  (verified). Fork-per-case is the natural stepping stone to the snapshot spike.
* **fd injection.** `ADDFD|SETFD|SEND` places a supervisor-owned fd into the target atomically with
  the syscall return. This is what makes "materialize, then let the kernel do the I/O" possible;
  with ptrace you would have to emulate every `read` yourself or rewrite the path argument in
  target memory (rr does the latter).
* **Composes with everything later.** Network (`socket`, `connect`, `sendto`, …) and time
  (`clock_gettime` *syscall*, `nanosleep`, `futex` timeouts) are just more syscall numbers in the
  same filter; scheduler control needs per-thread attribution (`req->pid`) and the ability to hold
  a thread blocked in the kernel indefinitely — a pending notification does exactly that.

ptrace keeps a role as a *debug aid* (single-stepping a failing case in rr/gdb still works because
we don't hold the tracer slot) and as a fallback for things seccomp cannot see (§4).

### 3.2 Process model: in-process by default, fork as opt-in isolation

* **Thread mode (default).** `Sandbox::install()` runs on the fuzz thread once (a seccomp filter
  cannot be removed, so it lives as long as the thread). It spawns the supervisor thread *before*
  installing the filter (threads created after inherit it). Outside a case every trapped call is
  answered `CONTINUE`, so an installed-but-idle filter costs ~9 µs per trapped call and nothing
  for the rest. Coverage capture, `CaseRng`, shrinking — all unchanged.
* **Fork mode (`Isolation::Fork`).** The fuzz thread forks per case; the child installs the filter
  (or inherits it from an already-filtered parent thread) and runs the harness closure; the parent
  serves the notifications and collects the result over a pipe (coverage counters live in shared
  memory: `memfd` + `MAP_SHARED` for the sancov counter region, same trick as AFL++'s forkserver).
  Buys: crashes/aborts become case results instead of killing the fuzzer, env vars can be applied
  with `clearenv/setenv` safely (single-threaded child), leaked fds/`chdir`/signal handlers cannot
  poison the next case, and it is literally the snapshot primitive (fork = CoW snapshot). Costs the
  §2.4 fork time per case.

The supervisor code is identical in both; only `TargetMem` (direct pointer vs
`process_vm_readv/writev`) and the "target is gone" signal (thread join vs `POLLHUP`/`pidfd`
readable) differ.

### 3.3 What gets trapped and how it is answered

BPF program (order matters, most frequent first):

```
nr in {read, pread64, readv, preadv}  && args[0] == URANDOM_FD  -> USER_NOTIF
nr in {read, pread64, readv, preadv}                             -> ALLOW      (native)
nr in {openat, openat2, open, statx, newfstatat, stat, lstat,
       readlink, readlinkat, access, faccessat, faccessat2,
       getrandom, getpid, gettid, uname, sysinfo}                -> USER_NOTIF
nr in {execve, execveat}                                         -> USER_NOTIF (env rewrite, §3.5)
seccomp, prctl(PR_SET_SECCOMP)                                   -> ERRNO(EPERM) (a nested filter could shadow ours)
default                                                          -> ALLOW
```

(`getdents64`, `fstat`, `lseek`, `mmap`, `close` are *not* trapped: they operate on injected fds.)

Supervisor handling, per syscall:

| syscall | non-virtual path / not ours | virtual |
|---|---|---|
| `openat(dirfd, path, flags, mode)` | `CONTINUE` | resolve path against declared tree (`dirfd` must be `AT_FDCWD` or an injected dir fd, else `CONTINUE`); materialize node on first touch (§3.4); supervisor `open()`s the materialized file/dir with the target's `flags & ~O_CREAT` and `ADDFD|SEND`s it. Or, per the node's `variant`, answer `ENOENT`/`EACCES`/`EMFILE`. Writes (`O_WRONLY/O_RDWR/O_CREAT/O_TRUNC`) hit the per-case tmpfs copy, so the target can write and re-read its own file. |
| `statx`/`newfstatat`/`stat`/`lstat` with a path | `CONTINUE` | materialize; supervisor runs the same `statx` on the materialized path; copy the struct into the target buffer (`TargetMem::write`); return 0. `AT_EMPTY_PATH`/fd-relative forms are `CONTINUE` (kernel handles the injected fd). |
| `readlink(at)` | `CONTINUE` | virtual symlink nodes: target string drawn from the case; write min(len, bufsiz) bytes; return that. |
| `access`/`faccessat(2)` | `CONTINUE` | 0 or `ENOENT`/`EACCES` per node variant. |
| `read`/`pread64`/`readv`/`preadv` on `URANDOM_FD` | n/a | draw `n = rng.range(0..=min(count, cap))` bytes (variant: full, short, `EINTR`); write to the buffer; return n. |
| `getrandom(buf, len, flags)` | n/a | same as above; `GRND_NONBLOCK` may also draw `EAGAIN`; `len` capped at a harness-configurable max (default 256) because the trace budget is 4096 bytes (§6). |
| `getpid`/`gettid` | n/a | fixed per case: `pid` drawn once (variant over a small interesting set: 1, 2, 4242, 32768, 4194304-1) and `tid = pid + thread index`. The supervisor's own threads are unfiltered, so libstd/glibc internals of the *fuzzer* are unaffected. |
| `uname` | n/a | struct filled from declared defaults with per-case variants (release string variants: `"6.8.0"`, `"5.4.0-generic"`, 64 non-NUL bytes to hit truncation bugs). |
| `sysinfo` | n/a | `uptime`, `totalram`, `freeram`, `procs` drawn as ranges over interesting sets (0, 1, MAX). |
| `openat("/proc/self/environ")` / `/proc/<own pid>/environ` | — | treated as a virtual file whose content is the declared env list serialized as `KEY=VAL\0…`. |
| `execve` (fork mode only) | `CONTINUE` after rewriting the `envp` array in target memory | see §3.5 |

Every "outcome" cell above is a `variant` and every "how many/which bytes" is a `range`, and all
draws go through the *one* `CaseRng` of the case, in syscall order (§6).

### 3.4 Virtual filesystem = declared tree + lazy materialization on tmpfs

The harness declares what is virtual (everything else is real and passes through):

```rust
let sb = Sandbox::builder()
    .file("/etc/app/app.conf", FileSpec::bytes(0..=512))          // contents: range of bytes
    .file("/etc/app/key.bin",  FileSpec::bytes(32..=32).absent_ok()) // may be ENOENT (variant)
    .dir("/var/lib/app", DirSpec::entries(0..=4, FileSpec::bytes(0..=64))) // getdents via real dir
    .symlink("/etc/app/current", LinkSpec::target_from(["/etc/app/app.conf", "loop", ""]))
    .env("APP_MODE", EnvSpec::one_of(["strict", "lenient", ""]))
    .urandom(UrandomSpec::default())                               // reads capped at 64 B each
    .identity(IdentitySpec::default())                             // pid/tid/uname/sysinfo
    .isolation(Isolation::Thread);
```

Materialization is *lazy*: a node is generated from the `CaseRng` the first time a syscall touches
it (so unopened files consume no draws and unrelated shrinking does not disturb them) into a
per-case directory `$XDG_RUNTIME_DIR/dowsing/<pid>/<case>/…` on tmpfs (`/dev/shm` fallback), and
the directory is removed at case end. Why materialize instead of emulating every `read`:

* zero-cost I/O after `open` (kernel does it; verified 13.9 µs `open+close` on a memfd vs a trap on
  every `read`),
* `mmap` of a config file, `fstat`, `lseek`, `getdents64`, `openat(dirfd, rel)` all Just Work,
* the minimized file already exists on disk in the exact bytes the target saw — the deliverable
  for the "minimized file is tiny" success criterion is a real file the user can open.

Ordering determinism: generation order = syscall order = program order for a single-threaded
target. For multi-threaded targets the supervisor serializes notifications, so the order is the
order in which the kernel queued them, which is only deterministic once the scheduler spike pins
thread interleavings (risk R2). Until then, a per-node *sub-seed* derived from
`(case seed, path hash)` — not the shared cursor — can be used as a fallback mode so contents don't
depend on arrival order; the trade-off is that `cautious()` then cannot shrink those bytes
structurally (only via the length variant), so it is opt-in.

Optional level 2 ("fault injection"): a `FileSpec::faults()` flag additionally puts the injected fd
into the fixed-fd table (`fd >= 1000`), making its `read/pread` trapped like urandom so that short
reads / `EINTR` / `EIO` become variants. Off by default because it costs ~8 µs per read.

### 3.5 Environment variables

There is nothing to intercept at run time: glibc and Rust std read `environ`, which `execve` copied
onto the initial stack. Options and the pick:

1. **Fork mode:** the forked child is single-threaded, so `clearenv()` + `setenv()` from the
   declared list before calling the harness closure is safe and exact. For targets that `execve`
   (spawn a helper), the `execve` trap rewrites `envp` in the target's memory before `CONTINUE` — the
   TOCTOU the man page warns about is irrelevant here (we are not a security boundary).
2. **Thread mode:** `std::env::set_var` is `unsafe` in Rust 2024 and races with other threads
   reading `environ`; we do it anyway *before* the case starts, on the fuzz thread, with the
   supervisor's guarantee that no filtered thread is running (the case has not started). Documented
   as best-effort; the fork mode is the exact one.
3. **Virtual `/proc/self/environ`** is served in both modes for targets that read the file.

Rejected: re-`execve` the whole test binary per case (≥1 ms plus dynamic loading; kills coverage
capture in-process) — that is a future "external target" mode, not this spike.

### 3.6 Supervisor loop

One `epoll` per supervisor thread, one supervisor thread per fuzz thread (so `ParallelCases`
scales with no shared lock on the hot path):

```rust
loop {
    for ev in epoll.wait(&mut events, timeout) {
        match registry[ev.token] {
            Source::Listener(fd)  => serve_notifications(fd),   // RECV → decode → answer, non-blocking
            Source::TargetGone    => finish_case(Gone),          // POLLHUP on listener / pidfd readable
            Source::Timer(t)      => time_module.fire(t),        // future: virtual clock deadlines
            Source::Socket(s)     => net_module.readable(s),     // future: fake peers
            Source::Control       => handle_command(),           // start_case / end_case / shutdown
        }
    }
}
```

Rules that make it shareable across spikes:

* **Never block in RECV**; always `epoll` first (POLLIN = notification pending, POLLHUP = all
  filtered tasks gone, and the BUGS entry in §2.2).
* **A notification is a resumable object** (`Pending { id, tid, nr, args, deadline }`). Modules
  may *hold* it (network: wait for the fake peer; time: wait for the virtual clock to advance;
  scheduler: deliberately leave a thread parked in the kernel until it is picked to run) and
  answer later. `ID_VALID` before every deferred write or `SEND`; `ENOENT` on `SEND` means the
  syscall was interrupted by a signal and will be re-issued — release any injected resources.
* **All `CaseRng` draws happen on the supervisor thread** during a case. The rng is moved into the
  session at `start_case` and returned at `end_case`, so the harness closure and the supervisor
  never touch it concurrently (in thread mode the harness's own `rng.range(...)` calls run on the
  fuzz thread while the supervisor is idle, and the supervisor draws only while the fuzz thread is
  blocked in a trapped syscall — a `Mutex<CaseRng>` makes this sound, and it is uncontended).
* **Per-thread attribution** by `req->pid` (tid) so the scheduler spike can keep a run-queue of
  parked notifications and pick which one to answer next (that *is* deterministic scheduling for
  the syscall-blocking points; user-space-only races need the separate scheduler design).

## 4. Alternatives considered and rejected

| alternative | why not (for this spike) |
|---|---|
| **ptrace `PTRACE_SYSCALL`** (strace-style) | 2 stops per syscall, ~16 µs measured, every syscall stops incl. `read`/`futex`/`mmap`; single tracer per task (conflicts with gdb/rr and with `cargo test` threads); a thread cannot trace a sibling in its own process, so it forces the fork model. |
| **seccomp `RET_TRACE` + ptrace** (rr's fast path) | Selective and 8.7 µs, but still a ptracer: same ownership/in-process problems; no fd injection, so files have to be served by rewriting the path argument in target memory (rr does this) and syscall results by `SETREGS`. rr additionally needs perf-counter-based scheduling and a preloaded syscall buffer to hit its overheads — a much larger system. |
| **`SECCOMP_RET_TRAP` + in-process `SIGSYS` handler** (gVisor systrap) | Fastest possible in-process path (no other thread involved), but the handler runs *on the target thread* with async-signal-safety constraints, cannot inject fds, and any Rust code in the handler (allocation, `Mutex`) is UB-prone. systrap needs a custom stub/sysmsg protocol to escape that. Kept as a possible future optimisation for `getrandom`/`getpid` only. |
| **`LD_PRELOAD` / symbol interposition of libc** | Misses raw syscalls (Rust std calls `libc::getrandom`, but `getrandom` crate uses `syscall(2)`; static-pie targets, Go, musl); breaks under `-Cprefer-dynamic=no`; leaks into the fuzzer's own libstd. Interposition is the *mock* we are trying to remove. |
| **FUSE filesystem for the virtual tree** | Needs `/dev/fuse` and `fusermount` (setuid) or a user namespace with mount privileges; ~2 round trips per operation; all processes on the box see it; no per-case isolation without one mount per case. Materializing on tmpfs gives the same "real fd" property for free. |
| **Mount namespace + bind/overlay of a per-case dir** (`unshare -Urm` works here) | Attractive for `chroot`-like fidelity, but needs a *process* per case (namespaces are per process for mounts), can't be done for a single thread, and `pivot_root`/overlayfs-in-userns has kernel-version quirks. Keep as an optional enhancement for fork mode (mount the per-case tmpfs over `/etc/app` to also catch `execve`d children). |
| **userfaultfd for memory-level snapshot** | `unprivileged_userfaultfd=0` on this box — unavailable. |
| **Nyx/kAFL (KVM snapshots, Intel PT)** | Out of scope by definition (full-VM). Their lesson we keep: snapshot restore must be cheaper than the work between snapshots, hence lazy materialization and fork-as-snapshot budgets in §2.4. |
| **AFL++ snapshot LKM / libAFL `QemuSnapshot`** | Kernel module or QEMU; not local-unprivileged-stock-kernel. libAFL's forkserver and its shared-memory coverage map are the pattern we copy for fork mode. |
| **Antithesis-style deterministic hypervisor** | Same as Nyx: whole-system determinism via a hypervisor. Their insight that *time is the hardest nondeterminism* is why time is a separate spike and why vDSO (§2.5) is flagged. |
| **Emulating every `read` in the supervisor** (no materialization) | ~8 µs per `read` (measured trap cost) versus ~0.1 µs native; breaks `mmap`, `sendfile`, `getdents64`; still needed as level-2 fault injection, not as the base. |
| **Serving files from a memfd instead of a tmpfs dir** | Works for files (verified), not for directories or symlinks, and can't be reopened by path after the first `open`. tmpfs dir subsumes it. |

## 5. Relationship to the other spikes (one supervisor, four modules)

* **Network:** `socket/connect/bind/listen/accept4/sendto/recvfrom/poll/epoll_wait` join the trap
  set. Peers are fake and driven by the case (`variant`: accept/refuse/reset/timeout; `range`:
  reply bytes). A `connect` notification is *held* until the module decides — the same
  `Pending` object as here. `recv` on a fake socket is the same "fixed-fd table" trick as urandom
  (fd ≥ 1000 → trapped), or a real `socketpair` fed by the supervisor for native speed.
* **Time:** `clock_gettime`/`gettimeofday` are vDSO (no syscall) — must be handled by patching the
  vDSO in the target (rr does; in-process we can `mprotect`+overwrite our own vDSO page mapping, or
  set `LD_SHOW_AUXV`-style `AT_SYSINFO_EHDR` removal at exec in fork mode). `nanosleep`,
  `clock_nanosleep`, `futex` with timeout, `epoll_wait` with timeout, `timerfd_*` are syscalls and
  become *held* notifications that the virtual clock releases. The `Timer` epoll source in §3.6 is
  their hook.
* **Scheduler:** thread-scoped filter + `req->pid` = per-thread parking points. Deterministic
  scheduling of syscall-blocking points falls out of "answer one held notification at a time"
  (Shuttle/Loom-style: the choice of which parked thread to resume is a `variant`, reproducible and
  shrinkable). Preemption at arbitrary user-space instructions (Loom's `yield` points) is *not*
  provided by this mechanism and needs its own design (perf-event-based like rr, or
  instrumentation); this spike must simply not preclude it — it does not, since the supervisor
  never assumes it is the only thing holding a thread.
* **Snapshot/rewind:** fork mode is the snapshot primitive (§2.4 numbers give the budget). The
  supervisor's per-case state (materialized nodes, urandom cursor, fd table, held notifications)
  must be snapshotted with the process: keep it in a plain `struct Session` that is `Clone`, and
  make the materialized tmpfs dir copy-on-fork (per-snapshot subdirectory, `reflink`/`copy_file_range`
  on tmpfs is a memcpy) — risk R8.

## 6. Plugging into `CaseRng` / `CoverageCapture` / `curious` / `cautious`

### 6.1 API surface (proposed, not final)

```rust
// examples/sandboxed_config.rs (demo target harness)
let sb = Sandbox::builder()/* §3.4 */.build()?;
for mut rng in curious().with_coverage(SancovCoverage::new()).take(200_000) {
    let mut session = sb.start_case(&mut rng)?;      // moves a CaseRng handle into the supervisor
    let outcome = catch_unwind(|| demo_target::run()); // unmodified target; reads files/urandom/env
    let cov = session.finish(rng)?.coverage_with_cost(session.cost())?;  // §6.3
    if outcome.is_err() { save(rng.fork_case()); break; }
}
```

`Sandbox::start_case` installs the filter on first use (thread mode) or forks (fork mode), resets
the session, and hands the `CaseRng` to the supervisor behind a `Mutex`. `finish` waits for all
filtered threads of the case to be quiescent, tears down the tmpfs dir, and gives the rng back so
the harness calls `coverage()`/`coverage_with_cost()`/`discard()` exactly as today. No change to
`CoverageCapture`: `start_capture` still happens when the iterator yields the rng, before any
syscall of the case, and `finish_capture` after; the supervisor's own code is not instrumented
(it lives in the `iterator-fuzz` crate, `cargo rustc --example` instruments only the example crate),
so its edges do not pollute the feature set. For `ParallelCases`, each worker thread gets its own
`Sandbox` supervisor (the trace-pc-guard capture is already per-thread).

### 6.2 Which choices are `variant` / `range` spans (so `cautious()` can shrink them)

All draws are made on the supervisor from the case's `CaseRng` at the moment of the syscall, using
the *public* `variant`/`range` API so the semantic/sequence spans are recorded exactly as if the
harness had drawn them:

| decision | span | shrinks toward |
|---|---|---|
| does virtual file `p` exist / `ENOENT` / `EACCES` / `EIO` | `variant(n)`; index 0 = exists | exists (boring) |
| file length | `range(min..=max)` length span | `min` |
| file bytes | items of that `range` — one `ChildRng` per byte (or per line for `FileSpec::lines`) so `SequenceDelete`/`SequenceProject` remove bytes/lines and the byte passes zero them | shorter, then zeros |
| line-structured config (`FileSpec::lines(0..=8, LineSpec)`) | outer `range` of lines, each line an inner `variant` (key) + `range` (value bytes) | fewer lines, first key, empty value |
| directory entry count / names | `range(0..=k)` of entries, name = `range(1..=16)` of bytes restricted to a safe alphabet; a `variant` for entry type (file/dir/symlink) | empty dir |
| symlink target | `variant` over declared targets (0 = the sane one) | sane target |
| urandom / `getrandom` returned length | `variant(3)`: full / short / `EINTR|EAGAIN`, then `range(0..=count)` only for "short" | full length |
| urandom / `getrandom` bytes | plain `fill_bytes` (draw span only) — zeros under `zero_tail` | zeros |
| pid / tid | `variant` over an interesting-set (index 0 = `4242`) | `4242` |
| `uname` release/nodename | `variant` over interesting strings | current kernel's real value |
| `sysinfo` fields | `variant` over interesting values (index 0 = realistic) | realistic |
| env value | `variant` over declared values (0 = default) or `range` of bytes for free-form values | default / empty |
| env var present | `variant(2)` (0 = present) | present |
| (level 2) `read` on a fault-injected fd | `variant`: full / short(`range`) / `EINTR` / `EIO` | full |

Because `cautious()` already runs `SequenceDelete`, `SequenceProject`, length-span shrinking,
variant-span shrinking, draw-span zeroing and dictionary repair, no new shrinker passes are needed.
The dictionary from `sancov`'s comparison feedback (`mode = strict` string compares in the target)
flows into file bytes automatically because those bytes are ordinary draws.

Budget: `MAX_PREFIX_LEN = 4096` bytes of trace are structurally shrinkable; draws past it come from
the seeded fallback `SmallRng` (still deterministic per seed, but not shrinkable). Defaults are
chosen so a case fits: file ≤ 512 B, urandom reads ≤ 64 B each, `getrandom` ≤ 256 B; the sandbox
counts bytes drawn and exposes `session.trace_overflow()` so the harness can `discard()` cases that
blew the budget instead of getting un-shrinkable reproducers.

### 6.3 `CaseCost` and `discard()`

* `CaseCost` = total materialized bytes (sum of file lengths + env bytes + urandom bytes actually
  read) + 16 × number of non-default variants (`ENOENT`, short read, weird pid…). This makes
  `cautious()` prefer "one small file, nothing exotic" reproducers even when two candidates have the
  same trace length.
* `discard()` when: the target did not touch any virtual input (the case is uninformative for this
  harness), the trace budget overflowed (§6.2), the target exited via `std::process::exit` in
  thread mode (we cannot observe the result), or the supervisor had to answer a syscall it does not
  model (logged as `Unsupported(nr)`; §7 R3) — discarding keeps such cases out of the corpus rather
  than letting them look like new coverage.

### 6.4 Replay

`Case::replay()` is unchanged: the same `Case` fed to `start_case` reproduces the same materialized
files, env, entropy and identity because all of them are draws. The demo additionally writes the
materialized tree to `target/dowsing-repro/<hash>/` on failure so a human can `cat` the minimized
`app.conf`.

## 7. Risks and unknowns

* **R1 Non-virtual path cost.** Every `openat`/`statx` in a filtered thread pays ~9.5 µs even for
  real files (`CONTINUE`). A target that opens hundreds of real files per case (`/proc`, `/sys`,
  locale data) slows 10×. Mitigations: keep the trap list minimal; measure the demo; if needed,
  add a BPF fast path on `args[1]` *pointer ranges* (BPF can't deref, but a harness that knows its
  path strings live in `.rodata` could allowlist that address range — hacky, so measured first).
* **R2 Multithreaded targets → draw order.** With real parallelism the order in which two threads'
  notifications arrive is racy, so file contents could differ between runs → non-reproducible
  case. Mitigation now: per-node sub-seed fallback (§3.4); real fix: scheduler spike. Detectable:
  the supervisor records the (tid, nr) sequence and the replay verifier flags divergence.
* **R3 Unmodelled syscalls / flags.** `openat2`, `O_PATH`, `O_TMPFILE`, `renameat2`, `*xattr*`,
  `inotify`, `fanotify`, `mmap(MAP_SHARED)` writes to a virtual file, `copy_file_range`,
  `readlinkat(fd, "")`, `AT_EMPTY_PATH` variations. Policy: unknown → `CONTINUE` for non-virtual
  paths, `ENOSYS`+`Unsupported` marker (→ `discard`) for virtual ones. The strace table (§2.5)
  covers Rust std; C/Go targets will surface more.
* **R4 Pointer validity / EFAULT.** In thread mode a bad pointer from the target would segfault the
  *supervisor* if it dereferenced directly. Use `process_vm_readv/writev` on `getpid()` (works for
  self, returns `EFAULT` cleanly) or `/proc/self/mem` `pread/pwrite` for all target buffers, and
  always `ID_VALID` before writing in fork mode.
* **R5 TOCTOU / signal interruption.** The man page's TOCTOU is about adversaries; we are not a
  security boundary. The real hazard is `SEND` → `ENOENT` because a signal (e.g. a `SIGALRM` from a
  test timeout, or the harness's own `catch_unwind` panic path) interrupted the blocked syscall: the
  kernel restarts it and we get a second notification for the same call. Draws must therefore be
  attached to the *materialized node*, not to the notification, so the retry sees the same data
  (idempotent answers), and injected fds must use `ADDFD_FLAG_SEND` (atomic) to avoid leaks.
* **R6 Filter is permanent and inherited.** The fuzz thread and everything it spawns stays
  filtered for the process lifetime; `cargo test` runs other tests on other threads, unaffected,
  but a test that spawns threads from the fuzz thread after the sandbox is done still traps. The
  idle supervisor must therefore run for the thread's whole life answering `CONTINUE`, and
  `Sandbox` must be `!Send` (tied to the thread it filtered). `PR_SET_NO_NEW_PRIVS` is also
  permanent and inherited — harmless for tests, surprising for a harness that then `execve`s a
  setuid helper.
* **R7 vDSO `getrandom` (kernel ≥ 6.11, glibc ≥ 2.41).** On newer boxes glibc's `arc4random` (and
  possibly the `getrandom()` wrapper — I have not verified which) uses the vDSO and never enters
  the kernel, bypassing seccomp. Rust std currently calls the `getrandom` syscall via libc; the
  `getrandom` crate uses raw `syscall(2)`. Mitigation shared with the time spike: patch/unmap the
  vDSO functions in the target. Not an issue on the 6.8 fleet; make the prototype assert
  `getrandom` was observed at least once in the demo so a bypass is loud.
* **R8 Snapshot interaction.** A memfd/tmpfs file materialized before a fork is *shared* between
  parent and child (same inode): a write by one snapshot's run is visible to a rewound run.
  Materialize per snapshot (subdirectory keyed by snapshot id; copy on branch), or make virtual
  files read-only by default and route writes through trapped, per-snapshot buffers. Unknown until
  the snapshot spike exists; the `Session` struct is designed to be `Clone` so it can be part of the
  snapshot.
* **R9 `std::process::exit` / abort in thread mode** kills the whole fuzzer; only fork mode turns
  it into a case result. The demo runs both modes so this is documented, not surprising.
* **R10 Coverage of the supervisor path.** If a future user compiles the whole workspace with
  sancov (not just the example), supervisor edges would appear as features that vary with the
  *syscall pattern* rather than the target — mostly harmless (they correlate with target behavior)
  but noisy. Mitigation: `#[no_sanitize]`-style attribute is not stable in Rust; document and
  measure.
* **R11 Numbers are from one box.** All latencies are Xeon 8559C / kernel 6.8 / idle; a laptop
  with `mitigations=auto` may double the syscall trap cost. The prototype re-measures and prints
  a table.

## 8. Prototype plan

Crate layout (all behind `--features sandbox`, Linux-only `cfg`):

```
src/sandbox/mod.rs         Sandbox, SandboxBuilder, Isolation, Session, start_case/finish
src/sandbox/bpf.rs         seccomp BPF program builder (nr + arg0 == URANDOM_FD rules), install()
src/sandbox/notif.rs       raw ioctl wrappers: RECV/SEND/ID_VALID/ADDFD, seccomp_notif sizes
src/sandbox/mem.rs         TargetMem { InProcess, Remote(pid) } read/write via process_vm_*/proc mem
src/sandbox/supervisor.rs  epoll loop (§3.6), Pending, per-tid attribution, POLLHUP handling
src/sandbox/vfs.rs         declared tree, lazy materialization to tmpfs, path resolution, statx copy
src/sandbox/entropy.rs     urandom fixed fd + getrandom answers
src/sandbox/identity.rs    getpid/gettid/uname/sysinfo answers
src/sandbox/env.rs         env application (thread/fork), /proc/self/environ, execve envp rewrite
src/sandbox/spec.rs        FileSpec/DirSpec/LinkSpec/EnvSpec/UrandomSpec/IdentitySpec -> draws (§6.2)
examples/sandboxed_config.rs   demo harness (curious then cautious, prints minimized file)
examples/demo_target/          the unmodified "application" the demo fuzzes (see below)
tests/sandbox_replay.rs        determinism + replay + shrink-size assertions (Linux only)
benches/sandbox_latency.rs     the §2 tables re-measured through the real code path
```

Dependencies: `libc` only (already the pattern in `src/sancov.rs`/`src/llvm.rs`); no `nix`/`seccompiler`
to keep the BPF and ioctl surface explicit and auditable.

### 8.1 Demo target (`examples/demo_target`)

An "application" that knows nothing about dowsing:

1. reads `APP_MODE` from the environment (`strict` | `lenient`, default `lenient`),
2. loads `/etc/app/app.conf` — a line-oriented `key = value` config (`mode`, `retries`, `name`,
   `seed`),
3. opens `/dev/urandom` and reads 8 bytes for a session nonce, calls `getrandom(16)` for a token,
4. lists `/var/lib/app/` and stats each entry,
5. prints a report including `getpid()` and `uname().release`.

Injected bug (the thing `curious()` must find and `cautious()` must minimize): when `mode = strict`
(from the file) *and* `APP_MODE=strict` (env) *and* `retries` parses to a value whose low byte
equals the first urandom byte, the retry-buffer indexing does `buf[retries - nonce[0] - 1]` and
panics on the underflow. The trigger needs fuzzer-controlled file content, env, *and* entropy at the
same time, and the sancov comparison dictionary (`"strict"`) is what makes it findable. Expected
minimized reproducer: a config of `mode=strict\nretries=1\n` (≈22 bytes; the memo's success bar is
"tiny") with urandom bytes all zero and `APP_MODE=strict`. In the `EnvSpec` for `APP_MODE`,
`strict` must *not* be variant index 0 (the shrink target): if it were, the shrinker would land on
it for free and the demo would prove less.

A second, C-only variant of the target (`demo_target_c.c`, built with `cc` from `build.rs` when
present) exercises `stat`/`newfstatat`/`readlink` code paths that Rust std does not emit.

### 8.2 Steps

1. `bpf.rs` + `notif.rs` + `mem.rs`: install thread-scoped filter, echo `getpid` (port of
   `unotif_thread.c` to Rust; ~200 lines). Test: pid is what the supervisor said.
2. `supervisor.rs`: epoll loop, `CONTINUE` default, `POLLHUP` exit, per-tid map. Test: filtered
   thread spawns a child thread; both attributed.
3. `vfs.rs` level 1: declared files → lazy tmpfs materialization → `ADDFD|SEND`; `statx`/`readlink`
   copy-out; directories. Test: `std::fs::{read, metadata, read_dir, read_link}` on virtual paths
   vs real paths untouched.
4. `entropy.rs` + `identity.rs`: fixed-fd urandom (BPF `args[0]` rule), `getrandom`, pid/tid/
   uname/sysinfo. Test: determinism across two runs of the same `Case`.
5. `spec.rs` + `Session` draws via public `variant`/`range`; `CaseCost`; `discard` rules;
   `trace_overflow`.
6. `examples/sandboxed_config.rs` + demo target: `curious()` until panic, `cautious()` to
   minimize, print the minimized `app.conf`, env and nonce. Assert in `tests/sandbox_replay.rs`
   that (a) the found case replays to the same panic 3×, (b) minimized file ≤ 32 bytes, (c)
   minimized urandom bytes are all zero.
7. `Isolation::Fork`: fork per case, listener via `pidfd_getfd`, `TargetMem::Remote`, shared-memory
   sancov counters, exit-status → outcome, `setenv` in child. Same tests pass in fork mode.
8. `benches/sandbox_latency.rs` + README section; write numbers into this memo's §2 as a
   "prototype re-measurement" table.

Estimated effort: steps 1–6 one session, 7–8 a second.

### 8.3 What will be measured

* Determinism: 1 000 replays of the found `Case` produce byte-identical materialized trees,
  identical `getrandom` bytes, identical panic message (thread and fork modes).
* Trap latency through the real Rust path: `getpid`, `CONTINUE openat`, virtual `openat`+`read`,
  urandom `read(8)`, `getrandom(16)` — compare to the §2 C numbers (expect ≤ 1.2×).
* Throughput: cases/s of the demo harness in thread mode vs fork mode vs the same harness with
  the sandbox disabled (mocked inputs) — the price of "no mocks".
* Passthrough tax (R1): cases/s of a target that opens 100 real files per case, with and without
  the filter.
* Time-to-bug: median iterations for `curious()` to hit the injected panic over 20 seeds, with and
  without cmp-dictionary feedback.
* Minimization: bytes of `app.conf` and total `CaseCost` before/after `cautious()`; wall time of
  `cautious()`; number of `SEND → ENOENT` retries observed (R5).
* fork mode: cases/s at demo RSS, and the §2.4 curve re-measured with a real sancov counter map
  mapped `MAP_SHARED`.

## 9. References consulted

* `seccomp_unotify(2)`, `seccomp(2)`, `pidfd_getfd(2)`, `process_vm_readv(2)`, `ptrace(2)`
  (man7.org; man pages are not installed on the box). Key facts used: `POLLHUP` semantics after the
  last filtered task is reaped; BUGS: blocking `RECV` after target exit hangs; `SEND`→`ENOENT` and
  `SA_RESTART` re-notification; `ADDFD_FLAG_SEND` atomicity; `CONTINUE` is not a security boundary.
* rr: "Engineering Record And Replay For Deployability" (O'Callahan et al., 2017) — ptrace context
  switches were their bottleneck; seccomp-bpf used to *suppress* ptrace traps; single-core
  scheduling for determinism; vDSO/syscallbuf patching.
* gVisor platform guide — `systrap` (`SECCOMP_RET_TRAP` + `SIGSYS` in-process) replaced the
  ptrace platform in 2023 for performance; ptrace platform deprecated.
* AFL++ forkserver / AFL-Snapshot-LKM README (fork is slow, 20–360 % speedup from a kernel-module
  snapshot; explains why fork stays opt-in here) and libAFL's forkserver executor (shared-memory
  coverage map).
* Nyx / kAFL — KVM-based snapshot fuzzing; out of scope but sets the "restore must be cheaper than
  the work" bar.
* Shuttle (random scheduling with PCT, replayable schedules) and Loom (exhaustive/DPOR
  permutations) — the scheduler module's choice of which parked notification to resume is a
  `variant`, giving Shuttle-style random scheduling and Loom-style deterministic replay from the
  same mechanism.
* Antithesis, "So you think you want to write a deterministic hypervisor?" — time as the hardest
  source of nondeterminism; motivates keeping time a separate module with vDSO handling.
* Hypothesis internals (choice-sequence shrinking toward shortlex-minimal; `shrink_towards`) and
  proptest (`ValueTree::simplify/complicate`) — dowsing's `range`/`variant` spans already give the
  same "shrink the structured choice, not the bytes" property, so the sandbox must express every
  decision as such a choice.

## 10. Prototype outcome (what changed relative to the plan)

Built and measured; details, commands and tables are in [`README.md`](README.md).

* **Standalone crate instead of `--features sandbox` in the root.** The spike rules require
  `spikes/fs-env-intercept/` with its own `[workspace]`; the module layout of §8 is kept
  (`bpf/notif/mem/supervisor/vfs/entropy/identity/env/spec` + `draw`, `fs`), and the root crate is
  untouched. `rand` is a dependency (deterministic expansion of large entropy reads); `libc`
  otherwise.
* **CPU pinning is the biggest win, and was not in the plan.** The §2 numbers (~8 µs per trapped
  call) were measured with fuzz thread and supervisor free to run on different CPUs. The same
  round trip pinned to one CPU is ~2.4 µs (getpid), `CONTINUE` passthrough 4.4 µs instead of 9.5,
  and the demo target runs 17k cases/s instead of 7.4k. `Sandbox::install()` pins by default;
  `Options { pin: false }` opts out. Consequence for §3.6/§5: one fuzz/supervisor pair per CPU is
  the natural `ParallelCases` layout. Risk R1 shrinks accordingly (passthrough tax 3.4 µs/open).
* **Rust path unpinned is ~1.4× the C numbers** (12 µs vs 8.4 µs for getpid): epoll + mutex +
  `ID_VALID` before writes. Pinned it is 3.4× faster than the C baseline, so the "≤ 1.2× C"
  target in §8.3 is met only with pinning.
* **`CaseCost` counts non-zero entropy bytes** in addition to §6.3's terms; without it `cautious()`
  had no reason to zero served randomness (byte passes do not reduce trace length or features).
  With it the minimized demo entropy is `[3, 0, 0, ...]` — `3` because the demo's `retries` default
  is 3 and dropping the `retries=` line is cheaper than zeroing one byte, so the minimized file is
  `mode=strict\n` (12 bytes) rather than §8.1's predicted 22.
* **Per-sandbox urandom fd window** (`1000 + 8k .. +8`) instead of one fixed fd, so several
  `Sandbox`es (one per test thread / worker) coexist in a process; the BPF program compares
  `args[0]` against the window.
* **In-memory copy of every materialized file** so replay assertions and the repro dump need no
  filesystem read-back; per-case tmpfs trees are removed by an unfiltered janitor thread
  (`remove_dir_all` on the filtered fuzz thread would pay a `CONTINUE` trap per `statx`/`openat`).
* **`Draw::sequence`** was added to the harness-facing draw API so line-structured files shrink by
  whole lines (`SequenceDelete` on the root crate's existing spans); the demo's `app.conf` is
  generated this way.
* **`--raw` (flat byte file) does not find the bug** in 200k cases: Rust string `==` is `bcmp`,
  which `trace-compares` does not see and `src/sancov.rs` has no memcmp hooks. Root-crate follow-up.
* **Not built (as planned for a second session): step 7 `Isolation::Fork`.** `TargetMem` is
  pid-parameterized and the fork primitives were verified in §2.2, but the shared sancov counter
  map needs a small root-crate hook.
* `unotify` behaviour as predicted: `POLLHUP` arrives when the filtered thread exits, the demo
  and time-to-bug runs reported `SEND retries = 0`, `ADDFD|SETFD|SEND` works for reopening the
  same slot after `close`, and threads spawned by the target report through the same listener with
  their own tid (`tests/smoke.rs`).
