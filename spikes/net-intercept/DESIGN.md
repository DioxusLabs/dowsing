# Spike `net-intercept`: syscall-level network interception for dowsing

Status: design memo, no prototype yet. Everything below was checked on the machine described in
§1 unless explicitly marked *unverified*.

## 0. TL;DR

Recommendation: **seccomp user notification (`SECCOMP_RET_USER_NOTIF`) in a forked child, with
kernel `socketpair`s as the backing objects for every fake socket.** The fuzz harness process is
the supervisor. It answers the *control plane* (`socket`, `connect`, `bind`, `listen`, `accept4`,
`getsockopt(SO_ERROR)`, `getpeername`, `getsockname`, `setsockopt`, `shutdown`, `close`) from
`CaseRng` draws, and it *gates* the *data plane* (`recv*`, `read*`, `send*`, `write*`, `poll`,
`ppoll`, `select`, `epoll_wait`, `epoll_pwait*`): on each notification it decides which peer
events happen now, materialises them by writing/`shutdown`ing its own end of the relevant
socketpairs, then lets the kernel execute the target's original syscall unchanged with
`SECCOMP_USER_NOTIF_FLAG_CONTINUE`. The kernel therefore provides buffering, partial reads,
`MSG_PEEK`, EOF, `EPOLLRDHUP`, edge-triggering and mixing with the target's *real* fds (tokio's
waker `eventfd`, `timerfd`, pipes), while the fuzzer decides *what* and *when*. Nothing in the
target is mocked; `std::net` and tokio/mio both work through the same path (verified by strace
inventory, §3).

Measured on this host (§2): a user-notification round trip costs **~2.2–2.6 µs** per intercepted
syscall when the supervisor uses `SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP` (or shares a CPU with the
target), **~8–9 µs** unpinned without it; ptrace costs 2–4× more per syscall and LD_PRELOAD is
cheap but cannot be made coherent. `fork()` of a 10 MiB-RSS process costs ~150 µs (~300 µs
including child exit and `waitpid`), so a fork-per-case sandbox is affordable and is also the
on-ramp to snapshot/rewind later.

## 1. Environment actually observed

| Item | Observed |
|---|---|
| Kernel | `6.8.0-1061-aws`, x86_64, 8 CPUs |
| Rust | 1.98.1 stable |
| `kernel.yama.ptrace_scope` | 1 (parent may trace descendants; `strace -p <unrelated pid>` fails, verified) |
| `vm.unprivileged_userfaultfd` | 0 |
| CRIU | absent |
| `strace`, `gdb`, `perf`, `gcc` | present; `clang` absent |
| Unprivileged seccomp user notification | works (`PR_SET_NO_NEW_PRIVS` + `SECCOMP_FILTER_FLAG_NEW_LISTENER`) |
| `SECCOMP_IOCTL_NOTIF_ADDFD` (+`SETFD` to fd 1000) | works |
| `SECCOMP_IOCTL_NOTIF_SET_FLAGS(SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP)` | works |
| `pidfd_getfd(pidfd_of_child, fd, 0)` | works from the parent |
| `process_vm_readv` on the child | works |
| Base crate | `cargo test` 54 passed; `cargo clippy --all-targets` no errors (two pre-existing warnings) |

## 2. Measurements (throwaway C programs, not committed)

All numbers are per intercepted syscall, wall-clock, tight loop, 100k–200k iterations, `-O2`.
Baseline: an uninstrumented `getpid` costs 0.10–0.13 µs.

### 2.1 seccomp user notification round trip

Child issues `getppid` (filtered `SECCOMP_RET_USER_NOTIF`); supervisor thread does
`NOTIF_RECV` → `NOTIF_SEND(val=0)`.

| Configuration | µs / call |
|---|---|
| unpinned, no sync wake | 8.3–9.3 |
| child and supervisor pinned to the same CPU | 2.17 |
| child CPU 2, supervisor CPU 3 | 7.54 |
| unpinned, `FD_SYNC_WAKE_UP` | **2.58** |
| same CPU, `FD_SYNC_WAKE_UP` | 2.19 |
| separate CPUs, `FD_SYNC_WAKE_UP` | 7.32 |

Interpretation: the cost is dominated by cross-CPU wakeups. `FD_SYNC_WAKE_UP` (kernel ≥ 6.6, so
present here) makes the scheduler run the woken task on the current CPU and gets the same benefit
as pinning without having to pin. This is the configuration the prototype should use.

### 2.2 ptrace

| Mode | unpinned µs / syscall | pinned µs / syscall |
|---|---|---|
| `PTRACE_SYSCALL` (entry + exit stop for *every* syscall) | 15.9 | 5.8–7.0 |
| `SECCOMP_RET_TRACE` selective stop (2 stops per intercepted call) | 20.8 | 10.8 |
| `SECCOMP_RET_TRACE`, unfiltered syscalls (`getpid`) | 0.12 | 0.12 |
| `PTRACE_SYSEMU` (1 stop per syscall) | ≈ 9–10 *(unverified: the harness needed several fixes; treat as order-of-magnitude only)* | ≈ 4–5 *(same caveat)* |

Interpretation: a ptrace stop is roughly one notification round trip, and faithful emulation needs
two stops per syscall (entry to decide, exit to rewrite the result) unless `SYSEMU` is used for
every syscall. Net: 2–4× the cost of seccomp notification, plus the operational costs in §5.

### 2.3 fork() cost versus RSS

`fork()` + child `_exit(0)` + `waitpid`, parent RSS fully touched before forking; optional child
touching one page per 64 KiB (to simulate COW faults during a case).

| RSS | `fork()` returns after | fork+exit+wait | … with child touching pages |
|---|---|---|---|
| 10 MiB | 151 µs | 308 µs | 623 µs |
| 100 MiB | 870 µs | 1.9 ms | 4.7 ms |
| 1000 MiB | 4.6 ms | 11.0 ms | 39 ms |

Interpretation: fork-per-case gives ~3k cases/s at 10 MiB RSS before any interception cost; a
typical protocol-client exchange costs 6–15 intercepted syscalls (§3) ≈ 15–40 µs at 2.5 µs each,
so **fork, not interception, is the per-case bottleneck**. Snapshotting by fork at "connection
established" is cheap enough to be the rewind primitive later.

### 2.4 LD_PRELOAD on a Rust `std::net` binary

`nm -D` on a debug `std::net` client shows `connect@GLIBC_2.2.5`, `socket@`, `send@`, `recv@`,
`poll@`, `getaddrinfo@` as dynamic imports; a tokio client additionally imports `epoll_ctl@`,
`epoll_wait@`. A 6-line preload `.so` overriding `connect` made `TcpStream::connect` to a closed
port "succeed". The subsequent `send` then went to the *real* unconnected kernel socket and
failed with `EPIPE`, which is exactly the coherence problem discussed in §5.3.

## 3. Syscall inventory of the two target shapes (strace on this host)

### `std::net` client, `TcpStream::connect("127.0.0.1:p")`, write, read

```
socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP)   = 3
connect(3, {AF_INET, 127.0.0.1:p}, 16)                  = 0
sendto(3, "GET / …", 18, MSG_NOSIGNAL, NULL, 0)         = 18
recvfrom(3, …, 256, 0, NULL, NULL)                      = 156
```

std also runs `poll([{fd=0},{fd=1},{fd=2}], 3, 0)` once at startup (fd sanity check) and one
`getrandom` (HashMap seeds). `connect_timeout` uses `O_NONBLOCK` + `poll` + `getsockopt(SO_ERROR)`.

### tokio `current_thread` client (mio)

```
epoll_create1(EPOLL_CLOEXEC)                            = 3
eventfd2(0, EFD_CLOEXEC|EFD_NONBLOCK)                   = 4          # waker
epoll_ctl(3, ADD, 4, {EPOLLIN|EPOLLRDHUP|EPOLLET})
socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK) = 6
connect(6, …)                                           = -1 EINPROGRESS
epoll_ctl(5, ADD, 6, {EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLET, data=…})   # 5 = dup of 3
epoll_wait(3, [{EPOLLOUT,…}], 1024, 1984)               = 1
getsockopt(6, SOL_SOCKET, SO_ERROR, [0], [4])           = 0
sendto(6, …, MSG_NOSIGNAL)                              = 18
epoll_wait(3, [{EPOLLIN|EPOLLOUT,…}], 1024, -1)         = 1
recvfrom(6, …, 256, 0, NULL, NULL)                      = 256
epoll_ctl(5, DEL, 6)
```

Observations that drive the design: the epoll set is **mixed** (a real `eventfd` plus fake
sockets), everything is `EPOLLET`, readiness for `connect` completion is `EPOLLOUT` followed by
`SO_ERROR`, and the runtime `dup`s the epoll fd. Name resolution in tokio happens on a
`spawn_blocking` thread (one `clone3`) and is plain glibc `getaddrinfo`.

### glibc `getaddrinfo("example.com")` on this host

```
socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK)   → connect("/var/run/nscd/socket") = ENOENT (×2)
openat /etc/nsswitch.conf, /etc/host.conf, /etc/resolv.conf, /etc/hosts
socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK); setsockopt(IP_RECVERR)
connect(3, {AF_INET, 127.0.0.53:53})
poll([{3, POLLOUT}], 1, 0); sendmmsg(3, [A query, AAAA query], 2, MSG_NOSIGNAL)
poll([{3, POLLIN}], 1, 5000); recvfrom(3, …, 2048, 0, &from, &fromlen) = 72
poll(...); recvfrom(3, …, 65536, …) = 96
socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE); bind; getsockname; sendto(RTM_GETADDR); recvmsg ×3
socket(AF_INET, SOCK_DGRAM); connect(3, {AF_INET, <answer>:0}); getsockname(3, …)    # RFC 3484 source probe, per answer
```

So "DNS interception" is really: a UDP socket to `resolv.conf`'s nameserver carrying
`sendmmsg`/`recvfrom`, a read-only netlink dump, and UDP `connect`+`getsockname` probes. All of it
is on fds we created, so all of it is under the same mechanism; no `getaddrinfo` hook is needed.

## 4. Recommended design

### 4.1 Process shape

```
harness (dowsing driver == supervisor)                child (target, forked from harness, no exec)
─────────────────────────────────────                 ────────────────────────────────────────────
for rng in curious()/cautious():                      prctl(PR_SET_NO_NEW_PRIVS)
  zero shared coverage page(s)                        seccomp(SET_MODE_FILTER, NEW_LISTENER, bpf) → listener fd
  fork() ──────────────────────────────────────────►  send listener fd to parent over pre-forked socketpair
  recv listener fd; SET_FLAGS(SYNC_WAKE_UP)           target_fn()  // real std::net / tokio code
  loop NOTIF_RECV → decide with rng → NOTIF_SEND       copy sancov counters → shared page; _exit(code)
  waitpid → Verdict{exit/signal/timeout}
  rng.coverage()  // ChildCoverage reads shared page
```

Why fork-without-exec of the harness binary: the child already contains the target code and the
sancov counters, no second binary or IPC protocol is needed, the seccomp filter (and
`NO_NEW_PRIVS`) is confined to the child, a target `exit`, `abort`, segfault or infinite loop is
isolated and killable with `SIGKILL`, and it is exactly the shape a later fork-based snapshot needs.
The filter and the listener are inherited by every thread the target spawns (tokio workers,
`spawn_blocking`), and each notification carries the issuing thread's tid in
`seccomp_notif.pid`, so one listener covers the whole target.

Alternative "thread mode" (target runs as a thread of the harness, filter installed only on that
thread) avoids `fork` and reuses `SancovCoverage` unchanged; it is listed as an optimisation in
§6, not as the default, because a stuck or crashing target then takes the fuzzer with it.

### 4.2 BPF filter: high fd range as the discriminator

seccomp BPF can only see syscall numbers and raw argument words, so it cannot know whether `read(fd)`
is a file or a socket. We make it able to: **every fake socket is installed with
`SECCOMP_ADDFD_FLAG_SETFD` at `fd ≥ FAKE_FD_BASE` (e.g. 1000)**, and the filter notifies on
`read/write/readv/writev/pread*/recv*/send*/close/fcntl/ioctl/shutdown/getsockopt/setsockopt/
getsockname/getpeername/dup*` only when `arg0 >= FAKE_FD_BASE`. Unconditionally notified:
`socket`, `socketpair`(AF_INET*), `connect`, `bind`, `listen`, `accept`, `accept4`, `poll`,
`ppoll`, `select`, `pselect6`, `epoll_wait`, `epoll_pwait`, `epoll_pwait2`, `epoll_ctl`, and
`io_uring_setup` (answered `ENOSYS` so runtimes fall back to epoll; io_uring SQEs are invisible to
seccomp). Everything else (`futex`, `mmap`, `clock_gettime`, file I/O at low fds, `write(1,…)`)
runs at native speed with no supervisor involvement — verified in §2.2 that unfiltered syscalls
cost 0.12 µs under a seccomp filter.

`dup`/`dup2`/`dup3`/`fcntl(F_DUPFD*)` on a fake fd are intercepted and re-issued by the supervisor
via `ADDFD` so the copy also lands in the high range (or `EMFILE` if the target demands a low fd).

### 4.3 Fake socket = kernel socketpair, peer end held by the supervisor

| Target syscall | Supervisor action |
|---|---|
| `socket(AF_INET/6, STREAM/DGRAM)` | `socketpair(AF_UNIX, same type \| CLOEXEC, …)`; `ADDFD{SETFD, SEND}` one end at the next free high fd → syscall returns that fd; keep the other end + a `FakeSocket{family, type, nonblock, state}` record. `O_NONBLOCK` from the `type` arg is applied to *our* copy of the flag; the injected fd gets the same flags via `ADDFD` semantics. |
| `connect(fd, addr)` | `variant(ConnectOutcome)`: `Ok`, `Refused(ECONNREFUSED)`, `Unreachable`, `TimedOut`, `Async(EINPROGRESS then SO_ERROR = variant(…))`. Records the fake peer address. For UDP sockets: always `Ok`. |
| `getsockopt(SO_ERROR)` | return the pending async-connect outcome; other options → `CONTINUE` when AF_UNIX supports them, else `0`. |
| `getpeername`/`getsockname` | write a synthesised `sockaddr_in[6]` into the target's buffer with `process_vm_writev` (after `NOTIF_ID_VALID`), return 0. Needed because the kernel would say `AF_UNIX`. |
| `setsockopt(TCP_NODELAY, SO_KEEPALIVE, …)` | return 0 (record for the log). |
| `bind`/`listen` | record; return 0. |
| `accept4` | `variant(AcceptOutcome)`: new connection (fresh socketpair + `ADDFD`), `EAGAIN`, `ECONNABORTED`, or *defer* (see §4.4). |
| `send*`/`write*` on a fake fd | `variant(SendOutcome)`: `CONTINUE` (kernel copies into the socketpair; supervisor later `recv`s it into the exchange log), `EPIPE`, `ECONNRESET`, `EAGAIN` (nonblocking only), short write (return `range(1..n)` and only later drain that many bytes). |
| `recv*`/`read*` on a fake fd | *gate*: draw `RecvEvent` (§4.5), materialise it on our end (`send` bytes, `shutdown(SHUT_WR)` for EOF), then `CONTINUE`; or return an errno directly (`ECONNRESET`, `EAGAIN`, `EINTR`). |
| `poll`/`ppoll`/`select`/`epoll_wait*` | *gate*: read the fd set / consult the epoll registration mirror, draw `ReadinessEvent`s for the fake fds in it, materialise them, then `CONTINUE`. If the fuzzer picked "nothing" and the timeout is finite → return 0 directly. If timeout is infinite and nothing real is pending → `EINTR` (std, mio and tokio all retry on `EINTR`) or force at least one event. |
| `epoll_ctl` | `CONTINUE` (the kernel registers our socketpair end, so readiness mixing is real) and mirror `{epfd → fd → events}` so gating knows which fake fds a given `epoll_wait` can observe. |
| `shutdown` | `CONTINUE` (AF_UNIX honours `SHUT_RD/WR`), record. |
| `close(fake fd)` | `CONTINUE`; drop our end after draining it into the log. |
| `sendmmsg`/`recvfrom` with an address (UDP, DNS) | `CONTINUE`, then for `recvfrom` with a non-NULL `src_addr` rewrite the address with `process_vm_writev` (kernel writes an empty `AF_UNIX` name). |
| `socket(AF_NETLINK)` and its traffic | `CONTINUE` (read-only address dump). |

Because the data plane is executed by the kernel with the target's real arguments, we never parse
`iovec`s or emulate `MSG_PEEK`, `MSG_WAITALL`, `SO_RCVBUF`, `EPOLLET`, `EPOLLONESHOT`,
`EPOLLRDHUP`, or `SHUT_RD`. The supervisor's only invariants are "the peer end is in the state the
fuzzer said" and "the target thread was blocked until the fuzzer said so".

### 4.4 Determinism and the scheduling hook

A target thread inside a notified syscall is asleep in `seccomp_do_user_notification` until the
supervisor answers. The supervisor therefore controls *when* every network-blocking point resumes,
and a multi-threaded target presents several pending notifications at once. Choosing which one to
answer next is `variant(pending.len())` — a Shuttle-style random scheduler restricted to network
blocking points. That is enough for this spike and is the seam where the future deterministic
scheduler plugs in (it will need futex/`clock_*` interception, out of scope here).

`accept4` "defer" and blocking `recv` "defer" are implemented by simply not answering that
notification until a later step decides to (the target is asleep, so deferring is free).

### 4.5 Where the bytes and the order come from: `CaseRng` spans

The supervisor never reads random bytes itself; every decision is a `CaseRng` call so that
`cautious()` can shrink it structurally. Enum variants are ordered so that **index 0 is the most
benign / terminating choice**, because `cautious()`'s `SemanticSimplify` drives `Variant` spans
toward zero and `Case::zero_tail` yields zeros past the recorded prefix.

```rust
// Whole exchange = a sequence: shrinkable by deleting or truncating events.
for _ in rng.range(0..=MAX_EVENTS) {
    match rng.variant(PeerEvent::COUNT) {            // 0 = Close (EOF), 1 = Data, 2 = Reset, 3 = Delay(EAGAIN/no readiness), 4 = ShortWrite …
        PeerEvent::Data => {
            let payload: Vec<u8> = match rng.variant(3) {      // 0 = well-formed frame, 1 = frame with one field fuzzed, 2 = raw bytes
                0 => protocol::gen_frame(&mut rng),            // uses range/variant internally
                1 => protocol::gen_mutated_frame(&mut rng),
                _ => rng.range(0..=MAX_CHUNK).map(|r| r.next_u8()).collect(),
            };
            let split_at = rng.variant(payload.len() + 1);     // chunking across recv calls
            …
        }
        …
    }
}
// Per blocking point:
let who = rng.variant(pending_notifications.len());            // which thread resumes
let outcome = rng.variant(ConnectOutcome::COUNT);              // per connect
let n_ready = rng.range(0..=fake_fds_in_set.len());            // which fds become ready in this epoll_wait
```

Spans and what shrinking does with them:

| Choice | Span | Shrink behaviour we rely on |
|---|---|---|
| Number of peer events / connections / accepted clients | `range` length | `SemanticLength` shortens the exchange; `DeleteSequenceItems` removes single events |
| Kind of each event, connect/accept outcome, which thread resumes, which fds are ready | `variant` | simplified toward 0 = Close / Ok / first thread / "no extra readiness" |
| Payload bytes | `range` of byte draws (items) | items deleted or zeroed; comparison-dictionary values from sancov help hit parser constants |
| Payload split point, short-write length, timeout choice | `variant(len+1)` / `range` | zero = "deliver whole", so shrunk cases stop splitting |
| Payload generator (well-formed / mutated / raw) | `variant` | zero = well-formed, so the minimised case shows the smallest deviation |

The exchange log (every intercepted syscall, its outcome, and the bytes the target actually sent)
is returned with the `Verdict` so a shrunk case can be printed as a readable transcript.

### 4.6 Coverage across the process boundary: `ChildCoverage`

`SancovCoverage` (`src/sancov.rs`) records the inline-8bit-counter ranges in
`__sanitizer_cov_8bit_counters_init`. Those ranges exist in the child too (same binary, forked). The
harness maps one `MAP_SHARED|MAP_ANONYMOUS` region *before* forking, sized to the sum of the
counter ranges. At the end of `target_fn` (and in a `SIGSEGV`/`SIGABRT` handler) the child copies
its counters into the shared region and `_exit`s. `ChildCoverage: CoverageCapture` has
`start_capture` = zero the shared region, `finish_capture` = convert the shared counters with the
same bucketing `SancovCoverage::counter_coverage` uses (factor that function so both backends
share it). Comparison-dictionary feedback (`trace-compares`) can be forwarded the same way later.

Caveat: `CaseRng` starts capture lazily on the first draw, which happens at the first
notification, i.e. *after* fork. `Sandbox::run` therefore calls `rng.variant(1)` before forking
so `start_capture` runs (and the shared region is zeroed) with deterministic timing. That
consumes zero prefix bytes worth of information (`variant(1)` always yields 0) but does record a
span; acceptable.

`ParallelCoverageCapture` for `ChildCoverage` is natural (one shared region per worker) and does
not need trace-pc-guards, unlike the in-process backend.

### 4.7 Harness API sketch (no code yet)

```rust
let sandbox = Sandbox::new(SandboxOptions { fake_fd_base: 1000, case_timeout: 2s, .. });

for mut rng in curious().with_coverage(sandbox.coverage()).take(N) {
    let verdict = sandbox.run(&mut rng, || demo_client::main_once());   // forks, supervises
    if verdict.is_bug() {
        let case = rng.fork_case();
        let _ = rng.coverage();
        for mut v in cautious().with_coverage(sandbox.coverage()).with_case(case).take(M) {
            let verdict = sandbox.run(&mut v, || demo_client::main_once());
            if verdict.is_bug() { best = min(best, v.coverage_with_cost(verdict.exchange_len())) }
            else { v.discard() }
        }
        println!("{}", best_exchange.transcript());
    }
}
```

`coverage_with_cost` receives the number of exchange events so `cautious()` prefers the shortest
transcript among equally-covered reproductions. `verdict.is_bug()` is `exit code != 0 || signal`;
the demo target `panic!`s (abort on panic) on the injected parser bug, so the bug is observable
without any oracle plumbing.

## 5. Alternatives rejected

### 5.1 ptrace (`PTRACE_SYSEMU`, `PTRACE_O_TRACESYSGOOD`, register rewriting)

Pros: can rewrite arguments and registers (e.g. shorten an infinite `epoll_wait` timeout), inject
arbitrary syscalls into the target, and see every syscall. Cons that decided it:

* 2–4× the per-syscall cost of user notification (§2.2), and faithful emulation needs two stops.
* Whole-process, all-or-nothing tracing unless combined with `SECCOMP_RET_TRACE` — at which point
  the seccomp filter is already there and `RET_USER_NOTIF` is the cheaper, simpler action.
* One tracer per tracee: the user can no longer attach `gdb`/`rr`/`strace` to the target while it
  is fuzzed; `ptrace_scope=1` also forces the tracer to be the parent.
* Multi-threaded targets need the tracer to handle `clone` events, signal-delivery stops, group
  stops, `execve` and `PTRACE_EVENT_EXIT` correctly — rr's `Task` state machine exists because this
  is hard.
* No benefit for the data plane, where we want the kernel to do the work anyway.

Kept as a fallback tool for two narrow needs if they ever arise: injecting a syscall into the
target (we currently need none — `ADDFD` and `CONTINUE` cover fd injection and passthrough) and
rewriting an argument in place (we currently avoid it via `EINTR`/direct return).

### 5.2 LD_PRELOAD libc interposition

Verified to work on glibc-linked Rust binaries (§2.4). Rejected as the primary mechanism:

* Not coherent by construction: every libc entry point that touches the fd must be interposed or
  the real kernel object leaks through (the `connect`-faked / `send`-`EPIPE` result in §2.4).
  Faking epoll in userspace then means re-implementing epoll semantics for mixed fd sets.
* Bypassed by raw syscalls: static/musl builds, `libc::syscall`, inline `asm!`, io_uring, and
  crates using `rustix` with its default `linux_raw` backend on x86_64 (`polling`, `async-io`,
  `smol`, many others). glibc-internal calls (everything `getaddrinfo` does) don't go through the
  PLT either, so DNS could only be faked by replacing `getaddrinfo` wholesale.
* Same address space as the target: no isolation, no fork-snapshot story, no scheduling hook.

Possible later use: a `syscallbuf`-style accelerator (as in rr) that answers hot data-plane calls
in-process and only falls back to the kernel for control-plane calls. Not needed at 2.5 µs/call.

### 5.3 Pure user-space emulation of sockets and epoll (virtual fds, no socketpair)

Maximal control, but the supervisor would need to emulate readiness for mixed epoll sets that
contain real `eventfd`/`timerfd`/pipe fds (tokio always does), plus `EPOLLET`, `EPOLLONESHOT`,
`MSG_PEEK`, partial reads, `SHUT_RD`, and answer every `recv` by `process_vm_writev` into target
memory. The socketpair-backed design gets all of that from the kernel for free and keeps exactly
the same control over *when* events happen.

### 5.4 Real network namespace with a real loopback server

Needs `CLONE_NEWNET` (root or unprivileged user namespaces, which Ubuntu 24.04 restricts via
AppArmor) and reintroduces TCP timing, buffer sizes and kernel scheduling as sources of
nondeterminism. It also doesn't let the fuzzer choose per-syscall outcomes.

### 5.5 gVisor-style full syscall emulation (systrap), Nyx/kAFL, CRIU

systrap (seccomp `RET_TRAP` + SIGSYS handler + shared-memory dispatch to a sentry) is the same
insight as ours — ptrace stops are too slow — but reimplements the kernel; we want the real kernel
for everything but the peers. Nyx/kAFL need KVM (out of scope). CRIU is absent and needs root.

## 6. Risks and unknowns

1. **seccomp user notification cannot modify syscall arguments.** `CONTINUE` runs the original
   call. Mitigations already in the design: answer directly (`0`, errno), materialise state on our
   end first, or `EINTR` a blocking wait. Unknown: a target that treats `EINTR` from `epoll_wait`
   as fatal (mio/tokio/std retry; some hand-rolled loops may not).
2. **glibc `res_send` may validate the source address of DNS replies** (`recvfrom` on an
   `AF_UNIX` socketpair yields an empty name). *Unverified.* Mitigation: rewrite the address via
   `process_vm_writev` after `CONTINUE`… except a `CONTINUE`d syscall gives us no post-syscall
   hook. Fallback: fully emulate `recvfrom` on DNS sockets (write payload + address into target
   memory, return length) — small because DNS replies are single datagrams. Milestone 3 decides.
3. **TOCTOU by design.** Pointer arguments are read from target memory after the notification;
   another target thread could change them before `CONTINUE`. Not a security boundary here, but it
   means the exchange log can disagree with what the kernel did in adversarial multi-threaded
   targets. Use `NOTIF_ID_VALID` before every `process_vm_*` to avoid touching a dead thread.
4. **High-fd trick leaks**: a target that `dup2`s a socket to a low fd, passes fds over
   `SCM_RIGHTS`, or inspects `/proc/self/fd` can observe or escape the range. Intercept the `dup`
   family (§4.2); document the rest.
5. **io_uring** bypasses seccomp entirely. Returning `ENOSYS` from `io_uring_setup` covers libs
   with epoll fallbacks (`tokio-uring`/`glommio` have none — out of scope).
6. **`AF_UNIX` vs `AF_INET` behavioural gaps** on the passthrough path: `setsockopt` options
   the kernel rejects for `AF_UNIX` must be answered directly (we do); `SO_RCVBUF` sizes differ
   (`sysctl net.core.wmem_default` ≈ 208 KiB), so backpressure timing differs from TCP; `MSG_OOB`
   unsupported. Acceptable for fuzzing; note in the docs.
7. **Blocking `connect` on a socketpair is meaningless**, so `Async` connect is implemented as:
   return `EINPROGRESS`, hold `EPOLLOUT` back until the fuzzer's chosen step, then answer
   `SO_ERROR`. `EPOLLOUT` is naturally true on a fresh socketpair, so "connect still pending" must
   be modelled by *not letting the target observe* the fd until the step arrives: the gate for
   `epoll_wait`/`poll` must be able to return 0/`EINTR` even though the kernel would report
   readiness. This is the one place where the "kernel does readiness" story needs supervisor-side
   masking; mitigation is to create the socketpair lazily on connect completion and `ADDFD` a
   placeholder (`eventfd`) first, then `dup2`-replace via a second `ADDFD{SETFD}` onto the same
   fd number — `ADDFD` with `SETFD` onto an occupied fd has `dup2` semantics (kernel installs it
   with `receive_fd_replace`). *Unverified with an epoll registration outstanding on the replaced
   fd* (epoll tracks the underlying file, not the number, so the registration would have to be
   redone — mio does not expect that); a 20-line experiment in milestone 1 decides between this
   and plain supervisor-side masking.
8. **Per-case fork cost dominates** for small targets (~300 µs at 10 MiB RSS). Persistent mode
   (many cases per child, reconnecting) is straightforward for `std::net` clients and awkward for
   tokio runtimes; also "thread mode" (§4.1) removes fork entirely at the cost of isolation.
9. **Coverage handoff on crash** relies on a signal handler copying counters; a `SIGKILL` on
   timeout loses that case's coverage (acceptable: timeouts are findings).
10. **Kernel version surface**: `ADDFD` needs ≥ 5.9, `ADDFD_FLAG_SEND` ≥ 5.14, `SYNC_WAKE_UP` ≥ 6.6,
    `epoll_pwait2` ≥ 5.11. All present on 6.8; feature-detect and degrade (no sync wake → 9 µs).
    The `linux/seccomp.h` uapi header on this host predates `SECCOMP_IOCTL_NOTIF_SET_FLAGS`, so
    the prototype defines the ioctl numbers itself (the throwaway experiment already did).
11. **Prior art check on Antithesis/Nyx-style snapshotting** is out of scope, but the fork
    numbers (§2.3) suggest fork-at-connection-established as a viable local rewind primitive.

## 7. Prototype plan

Everything lives under `spikes/net-intercept/` as a separate workspace member (`iterator-fuzz`
stays untouched except for factoring the counter-bucketing helper out of `src/sancov.rs`).

### Files

```
spikes/net-intercept/
  Cargo.toml                  # crate `net-intercept`, deps: iterator-fuzz (path), libc, tokio (dev)
  src/lib.rs                  # pub Sandbox, SandboxOptions, Verdict, Exchange (transcript)
  src/bpf.rs                  # BPF program builder: syscall table + fd>=BASE predicate
  src/notif.rs                # seccomp_notif/resp/addfd structs, ioctl wrappers, NOTIF_ID_VALID, process_vm_{readv,writev}
  src/child.rs                # fork, NO_NEW_PRIVS, install filter, send listener fd, run target, copy counters, _exit
  src/supervisor.rs           # notification loop, pending-set scheduler, per-syscall handlers (control plane / gates)
  src/fake_socket.rs          # FakeSocket state, socketpair creation, epoll registration mirror
  src/peer_model.rs           # PeerEvent/ConnectOutcome/... enums (index 0 = benign) and their CaseRng generators
  src/coverage.rs             # ChildCoverage: CoverageCapture over a MAP_SHARED region
  src/dns.rs                  # milestone 3: DNS datagram synthesis
  examples/std_client.rs      # demo target A: std::net, length-prefixed frame protocol, injected parser bug
  examples/tokio_client.rs    # demo target B: same protocol on tokio current_thread
  examples/std_server.rs      # stretch: bind/listen/accept path with fuzzer-played clients
  benches/roundtrip.rs        # per-syscall overhead (§ measurements) as a reproducible bench
  README.md                   # how to build with sancov flags and run the demos
```

### Demo target and injected bug

A tiny binary protocol client: send `HELLO`, then loop `recv` frames `[u16 len][u8 kind][payload]`.
`kind = 2` frames carry a "compressed" payload `[u8 n][byte]` that expands to `n` bytes into a
fixed 64-byte buffer without checking `n` (the injected bug: index out of range → panic; with
`panic = "abort"` the child dies with `SIGABRT`). Reaching it requires the fuzzer to: complete the
connect, deliver a syntactically valid frame header, choose `kind = 2`, and choose `n > 64`. Chunked
delivery (`Data` split across `recv`s) exercises the client's reassembly path. Expected shrunk
transcript: `connect Ok; Data [len=2, kind=2, n=65, b]; Close`.

### Steps

1. **Mechanics** (`notif.rs`, `bpf.rs`, `child.rs`): reproduce the throwaway experiments in Rust:
   filter installs, listener arrives in parent, `getppid` round trip, `ADDFD{SETFD}` at 1000,
   `SYNC_WAKE_UP`. Bench in `benches/roundtrip.rs`. Also settle unknown #7 (ADDFD-replace under an
   epoll registration).
2. **Fake TCP client path, blocking** (`fake_socket.rs`, `supervisor.rs`, `peer_model.rs`):
   `socket/connect/send/recv/close` for `examples/std_client.rs` with `NoCoverage`. Success:
   fuzzer with a fixed seed drives the client through a full exchange without a server.
3. **Coverage** (`coverage.rs`): `ChildCoverage`; build the example with the sancov recipe from the
   README; confirm `curious()` grows coverage across cases and finds the bug; confirm `cautious()`
   shrinks to the expected transcript. Record cases-to-bug and shrink steps.
4. **Nonblocking / tokio** : `epoll_ctl` mirror, `epoll_wait`/`poll` gates, `EINPROGRESS`
   connect + `SO_ERROR`, `EAGAIN` injection. Success: `examples/tokio_client.rs` reaches the same
   bug and shrinks.
5. **DNS** (`dns.rs`): target connects by name; supervisor synthesises DNS answers (`variant`:
   one A record / NXDOMAIN / SERVFAIL / truncated / garbage) and handles the netlink dump and
   source-probe `connect`+`getsockname`. Resolves unknown #2.
6. **Server path** (stretch): `bind/listen/accept4` with fuzzer-played clients.
7. **Write-up**: measurements table, throughput, findings; feed back into the parent vision
   (scheduler hook, fork snapshot).

### What will be measured

* Per-syscall interception cost: notification round trip (direct answer) and gate+`CONTINUE`
  path, with and without `SYNC_WAKE_UP`, single- and multi-threaded target.
* Per-case cost breakdown: fork, filter install, exchange, `waitpid`, coverage copy; cases/s for
  the std and tokio demos at their real RSS.
* Cases until the injected bug is found (`curious()`, several seeds) versus `NoCoverage`.
* Shrink quality: events and bytes in the minimal transcript; number of `cautious()` iterations.
* Syscall coverage: which syscalls the demo targets issued that reached the supervisor
  unhandled (the supervisor logs and answers `ENOSYS` for anything unexpected).

## 8. Prior art consulted and what was taken

* **rr**: `SECCOMP_RET_TRACE` + ptrace for control, a preload `syscallbuf` to avoid stops on hot
  syscalls; confirms "one supervisor round trip ≈ one ptrace stop" and that avoiding the stop
  matters. We avoid ptrace entirely and keep preload as a possible accelerator.
* **AFL++ / libAFL forkserver and `InProcessForkExecutor`**: fork-per-case with coverage in shared
  memory; our `ChildCoverage` mirrors the shm map and the fork numbers in §2.3 justify it.
* **gVisor systrap**: seccomp-based interception without ptrace for speed, dispatching to a
  user-space "kernel". We take the mechanism choice but not the emulation.
* **Nyx/kAFL**: hypervisor snapshots; out of scope, but the fork measurements are the local stand-in.
* **Shuttle/Loom**: random (Shuttle) vs exhaustive (Loom) schedule exploration; our "which pending
  notification resumes" `variant` is Shuttle's PCT-less random scheduler over network blocking
  points.
* **Antithesis**: deterministic hypervisor answering every nondeterministic input; our supervisor
  is the local, network-only approximation.
* **Hypothesis / proptest**: shrinking over the choice sequence with structure-aware deletion;
  maps directly onto dowsing's `range` (length + item spans) and `variant` (toward 0) — hence the
  "index 0 is benign" convention in §4.5.

## 9. Man pages / kernel docs used

`seccomp_unotify(2)` (`SECCOMP_IOCTL_NOTIF_RECV/SEND/ID_VALID/ADDFD`, `SECCOMP_ADDFD_FLAG_SETFD`,
`SECCOMP_ADDFD_FLAG_SEND`, `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, TOCTOU notes), `seccomp(2)`
(`SECCOMP_FILTER_FLAG_NEW_LISTENER`, `PR_SET_NO_NEW_PRIVS`), `Documentation/userspace-api/seccomp_filter.rst`
(`SECCOMP_IOCTL_NOTIF_SET_FLAGS`, `SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP`), `pidfd_getfd(2)`,
`process_vm_readv(2)`, `ptrace(2)` (`PTRACE_SYSEMU`, `PTRACE_O_TRACESYSGOOD`,
`PTRACE_GET_SYSCALL_INFO`), `epoll(7)`, `socketpair(2)`, `unix(7)`, `resolv.conf(5)`.

## 10. What the prototype changed relative to this memo (post-implementation)

Everything below was decided by running the code on the host described in §1; the README has the
commands and numbers.

1. **No `epoll_ctl` mirror.** The plan (§4.3, step 4) kept a supervisor-side copy of every epoll
   interest list. strace of the tokio target showed mio `dup`s the epoll fd (`Registry::try_clone`
   for the waker) and registers fd 1000 through the duplicate, so a per-fd-number mirror missed
   registrations and `epoll_wait` gates saw an empty set (symptom: tokio reads timed out after a
   successful connect). The gate now reads `/proc/<pid>/fdinfo/<epfd>` (`tfd: N events: HEX`
   lines) at every `epoll_wait`, i.e. the kernel's own interest list, and `epoll_ctl` is no longer
   in the filter. Cost: one small `/proc` read per wait (~10 µs), no state to keep coherent.
2. **Async connect: plain masking, no placeholder/replace trick.** Risk 7's `ADDFD`-replace under an
   outstanding epoll registration was not needed. The socketpair is injected at `socket()`, a
   nonblocking `connect` returns `EINPROGRESS` and records the drawn outcome as `pending_error`; the
   fresh pair is `EPOLLOUT`-ready so mio sees the connect "complete" on its next wait and
   `getsockopt(SO_ERROR)` returns the drawn result. "Connect still pending for k steps" is thus not
   modelled; the peer's *timing* is expressed only on the read side. This was enough for
   `TcpStream::connect` + `tokio::time::timeout`; a stricter model would `EINTR` the wait.
3. **Infinite waits are forced, timed waits are skipped.** Instead of answering `EINTR` (risk 1),
   an infinite `epoll_wait`/`poll` whose gated fake fds all have nothing pending forces the first
   gated peer to draw a non-`WouldBlock` event (index range excludes it), so the target cannot hang
   and no target sees `EINTR`. For finite timeouts, if every gated peer drew `WouldBlock` and no
   fake fd is already readable, the supervisor answers `0` ("timeout elapsed") directly instead of
   letting the kernel sleep: the target's timeout logic runs in zero wall time (`time_skips` in the
   `Verdict`). Before this a `--kind-byte` tokio run had 22 timeouts in 3885 cases; after, 0 in
   30 000. Real fds in the same set (tokio's eventfd) are not affected because their readiness is
   reported by the target's next wait.
4. **Blocking `connect` on `std::net`** goes through the same path: `TcpStream::connect_timeout`
   is itself nonblocking-connect + `poll` + `SO_ERROR`, so the transcript shows `(EINPROGRESS)`
   for the std client too; plain `TcpStream::connect` (used by the `--dns` path) is answered
   `0`/errno directly.
5. **Coverage handoff uses `catch_unwind` + the root crate's `SancovCoverage`**, not a signal
   handler copying raw counters (§4.6, risk 9): the child runs the target under `SancovCoverage`
   (its sancov callbacks are process-global) and serialises `ExecutionFeedback` features and the
   panic message into the `MAP_SHARED` region before `_exit`. `counter_coverage` therefore did not
   need to be factored out of `src/sancov.rs`; the root crate is unchanged. Panics are reported as
   `Outcome::Panicked(Some(msg))`; real crashes (`SIGSEGV`) still lose coverage.
6. **DNS source address (risk 2) did not bite glibc 2.35** on this host: the resolver accepted the
   reply from the AF_UNIX socketpair (empty peer name) — the `--dns` transcripts show A + AAAA
   queries answered and the connect proceeding to `10.66.66.1`/`fd66::1`. The `recvfrom`
   emulation fallback was not implemented. Netlink passthrough was not needed (no `AF_NETLINK`
   socket observed with `AI_ADDRCONFIG` unset by `ToSocketAddrs`).
7. **`select`/`pselect6` are passed through ungated** (logged as unhandled) and the `dup` family on
   fake fds returns `EMFILE` (logged). None of the demo targets issue either.
8. **Unhandled syscalls are `CONTINUE`d, not `ENOSYS`ed** (§7 "what will be measured"): with the
   fd-range filter every notified syscall is on a fd we own, so letting the kernel run it on the
   socketpair is the safer default; the supervisor records what it did not model.
9. **Injected-bug shrink target.** The memo predicted `Data[kind=2, n=65]`. `cautious()` reliably
   reaches the 3-decision structure (connect Ok, send accepted, one data event; the trailing
   `Close` is deleted), but leaves `n` wherever discovery found it (72–255): dowsing simplifies
   variants toward index 0 and deletes range items, and there is no gradient toward 65 because
   smaller `n` is *benign*. A value-bisecting simplifier for range items would close the gap.
10. **Coverage did not speed up discovery for this bug** (18 cases with `NoCoverage` vs 236–692 with
    sancov at seed 1): the bug is one frame away from the entry point, so uniform random exploration
    hits it first while the coverage-guided iterator spends its early budget on novelty. The
    integration is still exercised end to end (23–249 features per case cross the fork).
11. **Dependencies.** `libc` and `rand` only; `nix` and `rayon` were not needed. `tokio` (`rt`,
    `net`, `io-util`, `time`, `macros`) is a *dev-dependency* used solely by `examples/tokio_client.rs`
    — the whole point of that example is to run the unmodified tokio/mio networking stack under
    the sandbox, which cannot be done without it.
12. **Measurements vs §2.** Rust reimplementation reproduces the C numbers: 2.6 µs/notification
    with `SYNC_WAKE_UP` or same-CPU, 8.3 µs unpinned without; `RET_ALLOW` filter overhead 44 ns;
    `ADDFD` 3.3 µs pinned / 8.4 µs unpinned; fork + filter + handoff + exit + reap 199 µs at 2 MiB
    RSS (§2.3 said 308 µs at 10 MiB). End-to-end: ~1300–1900 cases/s single-threaded for the demo
    targets (9 notifications per std_client case, 5 `CONTINUE`d).
13. **Not done from the plan:** the thread scheduler `variant` (§4.4; notifications are served in
    arrival order), persistent-child mode, `ParallelCoverageCapture`, netlink synthesis,
    `select` gating, `SCM_RIGHTS`/`/proc/self/fd` handling. Listed as next steps in the README.
