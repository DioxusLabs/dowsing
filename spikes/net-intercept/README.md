# net-intercept: syscall-level network interception for dowsing

The target's networking syscalls are intercepted with **seccomp user notification**
(`SECCOMP_RET_USER_NOTIF`) and answered by the dowsing harness, which acts as the supervisor of a
forked (no `exec`) child. Nothing in the target is mocked: `std::net::TcpStream`,
`tokio::net::TcpStream`, `TcpListener::bind/accept` and glibc `getaddrinfo` all run their real code
paths; the remote peer, the resolver, and the readiness of every socket are played by the fuzzer
from `CaseRng` draws. Design rationale and rejected alternatives are in [DESIGN.md](DESIGN.md);
section 10 there records where the prototype deviated from the memo.

## How it works

* **Filter.** The child sets `PR_SET_NO_NEW_PRIVS`, installs a classic-BPF filter via
  `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER)` and hands the listener fd to
  the parent through `pidfd_open`/`pidfd_getfd` (`src/bpf.rs`, `src/child.rs`, `src/notif.rs`).
  `socket`, `poll/ppoll/select/pselect6`, `epoll_wait/epoll_pwait/epoll_pwait2` always notify;
  `connect/bind/listen/accept(4)/get|setsockopt/getsockname/getpeername/shutdown/close/read/readv/
  recvfrom/recvmsg/recvmmsg/write/writev/sendto/sendmsg/sendmmsg/ioctl/fcntl/dup/dup2/dup3` notify
  only when `fd >= 1000`; `io_uring_setup` returns `ENOSYS`. Everything else runs unfiltered.
* **Fake sockets are kernel AF_UNIX socketpairs** (`src/fake_socket.rs`). On `socket()` the
  supervisor creates a pair, injects one end into the child at fd 1000+ with
  `SECCOMP_IOCTL_NOTIF_ADDFD{SETFD|SEND}` and keeps the other. The fd range is what lets the BPF
  filter tell sockets from files without any state.
* **Control plane answered, data plane gated** (`src/supervisor.rs`). `connect`, `accept`,
  `SO_ERROR`, `bind`, `listen`, `getsockname`… are answered directly from `CaseRng` draws. For
  `recv*/read/poll/epoll_wait` the supervisor decides which peer event happens (`Close`, `Data`,
  `Reset`, `WouldBlock`), materialises it on *its* end of the socketpair (write bytes / `shutdown`),
  then returns `SECCOMP_USER_NOTIF_FLAG_CONTINUE` so the kernel executes the original syscall:
  buffering, partial reads, `MSG_PEEK`, `EPOLLET`, mixing with real fds (tokio's eventfd) are all
  the kernel's. `send*/write` are `CONTINUE`d and the bytes are drained from the peer end.
* **Nonblocking / epoll.** A nonblocking `connect` gets `EINPROGRESS`; the fresh socketpair is
  already writable so mio sees the connect "complete" and `getsockopt(SO_ERROR)` reports the drawn
  outcome. `epoll_wait` reads the interest list from `/proc/<pid>/fdinfo/<epfd>` (the kernel's own
  view, so mio's dup'ed epoll fd is covered) and gates every fake fd registered for `EPOLLIN`. On an
  infinite wait at least one gated peer must produce an event (no hang); on a timed wait where every
  peer chose `WouldBlock` the supervisor answers `0` directly instead of sleeping ("time skip").
* **DNS** (`src/dns.rs`). UDP sockets are fake datagram sockets; the supervisor parses the question
  the resolver sends and replies with a synthesized A (`10.66.66.1`) / AAAA (`fd66::1`) answer,
  NXDOMAIN or SERVFAIL, chosen by `variant`.
* **Dowsing integration** (`src/sandbox.rs`, `src/peer_model.rs`, `src/harness.rs`). The exchange is
  `rng.range(0..=max_events)`; each decision is a `variant` (index 0 = the benign choice, so
  `SemanticSimplify` drives toward `Close`/`Ok`/`WouldBlock`); payload bytes are tracked draws.
  `Sandbox::run(&mut rng, target) -> Verdict` gives the outcome (`Ok`, `Panicked(msg)`, `Signaled`,
  `TimedOut`…), the transcript, the number of decisions, syscall counts and the bytes the target
  sent. The harness runs `curious()`, and on a bug `fork_case()` → `cautious().with_case(case)`,
  reporting `coverage_with_cost(decisions)` so the shortest transcript wins and `discard()`ing
  variants that do not reproduce.
* **Coverage across the fork** (`src/coverage.rs`). `ChildCoverage: CoverageCapture` maps a
  `MAP_SHARED|MAP_ANONYMOUS` region before fork; the child runs the target under the root crate's
  `SancovCoverage` (its counters are process-global, so the forked copy sees exactly the target's
  edges), catches the panic with `catch_unwind`, and serialises the resulting `ExecutionFeedback`
  features plus the panic message into the region; the parent's `finish_capture` reads them back.
  No root-crate change was needed (`CoverageId`, `CoverageSet`, `ExecutionFeedback::new` are public).

## Demo targets and the injected bug

`src/demo.rs` implements a length-prefixed frame protocol `[u16 len][u8 kind][payload]`.
`kind = 2` ("compressed") carries `[u8 n][u8 byte]` and expands `n` copies of `byte` into a fixed
64-byte buffer **without checking `n <= 64`**: `n >= 65` panics with
`index out of bounds: the len is 64 but the index is 64`. The examples are ordinary programs that
know nothing about the sandbox:

| example | what it does |
|---|---|
| `examples/std_client.rs` | blocking `std::net`: `TcpStream::connect_timeout(10.66.66.1:7000)`, `write_all("HELLO frames/1\n")`, `read_exact` a frame header and body, parse; `--dns` connects to `fuzz.invalid:7000` instead (glibc `getaddrinfo`) |
| `examples/tokio_client.rs` | `tokio` current-thread runtime, `tokio::net::TcpStream::connect`, `write_all`, `read_exact` under `tokio::time::timeout` (nonblocking socket, `EINPROGRESS`, `SO_ERROR`, epoll readiness) |
| `examples/std_server.rs` | `TcpListener::bind(0.0.0.0:7000)`, `accept` up to three clients, send the greeting, parse client frames |

`--no-coverage` runs with `NoCoverage`; without it the binary must have been built with the sancov
recipe (`build-sancov.sh`) or `ChildCoverage` will report no counters.

## Build and run (fresh clone, Linux x86_64, kernel >= 6.6 for SYNC_WAKE_UP, stable Rust)

```sh
git clone https://github.com/DioxusLabs/dowsing.git
cd dowsing && git checkout devin/spike/net-intercept
cd spikes/net-intercept

cargo test                         # unit test for the DNS codec + 2 end-to-end sandbox tests
cargo clippy --all-targets         # clean
cargo build --release --all-targets

# Blocking std::net client, no coverage: curious() finds the bug, cautious() shrinks it.
cargo run --release --example std_client -- --no-coverage --seed 1

# Same with sancov coverage crossing the fork (ChildCoverage).
./build-sancov.sh std_client
./target/release/examples/std_client --seed 1
./target/release/examples/std_client --dns --seed 1       # connect by name -> synthesized DNS
./target/release/examples/std_client --once --seed 3      # one case, every peer decision printed

# tokio current-thread client (nonblocking connect, epoll gating, time skips).
cargo run --release --example tokio_client -- --no-coverage --seed 1
./build-sancov.sh tokio_client
./target/release/examples/tokio_client --seed 1
./target/release/examples/tokio_client --kind-byte --seed 1   # frame kind drawn as a raw byte

# Server path: bind/listen/accept with fake incoming connections.
cargo run --release --example std_server -- --no-coverage --seed 1
./build-sancov.sh std_server
./target/release/examples/std_server --seed 1

# Per-syscall interception cost.
cargo bench --bench roundtrip
```

Common flags for all three examples: `--no-coverage`, `--seed N`, `--cases N` (discovery budget,
default 20000), `--shrink N` (minimisation budget, default 2000), `--verbose`, `--once`, `--no-sync`
(disable `SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP`). Clients also take `--raw` (arbitrary payload bytes
instead of frame-aware generation) and `--kind-byte`.

## Measured results (this host: Ubuntu, kernel 6.8.0-1061-aws, 8 vCPU, Rust 1.98.1)

Kernel feature probe: `user_notif: true, sync_wake_up: true, addfd: true, pidfd_getfd: true`.

### Per-syscall interception overhead (`cargo bench --bench roundtrip`, `getppid`, N = 200 000)

| configuration | ns / syscall |
|---|---|
| no seccomp filter | 87 |
| filter installed, `RET_ALLOW` | 131 |
| notify → answer value, SYNC_WAKE_UP off, unpinned | 8 295 |
| notify → `CONTINUE`, SYNC_WAKE_UP off, unpinned | 8 393 |
| notify → answer value, SYNC_WAKE_UP on, unpinned | 2 679 |
| notify → `CONTINUE`, SYNC_WAKE_UP on, unpinned | 2 730 |
| notify + `process_vm_readv(64 B)` → value, sync, unpinned | 3 730 |
| notify + `ADDFD(SETFD 1000 \| SEND)`, sync, unpinned (N = 20 000) | 8 372 |
| notify → value / `CONTINUE`, both pinned to cpu0 (sync on or off) | 2 605 – 2 639 |
| notify + `process_vm_readv(64 B)`, pinned | 3 187 |
| notify + `ADDFD`, pinned (N = 20 000) | 3 307 |
| fork + filter install + pidfd_getfd handoff + exit + reap | 199 µs / case (RSS 2.1 MiB) |

So an intercepted syscall costs ~2.6 µs (about 30× a raw syscall) once the supervisor and target
share a CPU or `SYNC_WAKE_UP` is on, and 8–9 µs otherwise; reading arguments adds ~0.5–1 µs, and
injecting an fd costs another ~0.7 µs pinned / ~5.7 µs unpinned. Runs vary by roughly ±20% between
invocations on this VM.

### Demo runs (`--seed 1`, single supervisor thread, one command each as listed above)

| run | discovery | minimisation | shrunk transcript |
|---|---|---|---|
| std_client `--no-coverage` | bug at case 18, 1918 cases/s | 2000 variants in 1.07 s, 451 reproduced | cost 3: `connect Ok; send 15 B; recv <- Compressed[n=83]; close` |
| std_client sancov | bug at case 291, 1851 cases/s, 23 features | 2000 in 1.24 s, 982 reproduced | cost 3, `Compressed[n=72]` |
| std_client `--dns` sancov | bug at case 80, 1303 cases/s | 2000 in 1.85 s, 79 reproduced | cost 5: A/AAAA `Resolves`, connect `10.66.66.1` Ok, send, recv `Compressed[n=117]` |
| tokio_client `--no-coverage` | bug at case 18, 1683 cases/s | 2000 in 1.28 s, 450 reproduced | cost 3: `connect EINPROGRESS; SO_ERROR=0; send; epoll_wait <- Compressed[n=83]; close` |
| tokio_client sancov | bug at case 236, 1412 cases/s, 249 features | 2000 in 1.48 s, 62 reproduced | cost 3, `Compressed[n=255]` |
| tokio_client `--kind-byte` sancov | bug at case 692, 1294 cases/s | 2000 in 1.64 s, 61 reproduced | cost 3, `Compressed[n=110]` |
| std_server `--no-coverage` | bug at case 16, 1560 cases/s | 2000 in 1.29 s, 65 reproduced | cost 3: `bind; listen; accept -> 1001; send; recv <- Compressed[n=225]; close` |
| std_server sancov | bug at case 7, 1303 cases/s, 39 features | 2000 in 1.45 s, 89 reproduced | cost 3 |

Cases-to-bug is not perfectly reproducible across runs even with the same seed (a fresh-clone
re-run of `tokio_client --seed 1` found it at case 184 instead of 236; the `--no-coverage` runs
repeated exactly). All runs: 0 timeouts, 0 supervisor errors, empty unhandled-syscall list (except the documented
`select`/`dup` pass-throughs, which none of the targets issue). A single std_client case is 9
notifications, 5 of them `CONTINUE`d (`--once` output). Per-case cost is dominated by fork/exit
(~200 µs) plus ~10 notifications (~30 µs) plus the harness; ~0.5 ms/case ≈ 1300–1900 cases/s.

Earlier, before time skipping, a `--kind-byte` tokio run had 22 timeouts in 3885 cases (tokio's
`timeout(2s)` wrapped a wait in which every peer chose `WouldBlock`, so the sandbox slept). With
time skips a 10 675-case run reported 910 skips and 0 timeouts, and a 30 000-case run 0 timeouts.

### Shrink quality

`cautious()` always reaches the minimal **structure** (3 decisions: connect outcome, send outcome,
one data event; `Close` deleted from the tail) and leaves `n` at whatever value it landed on
(72–255) rather than driving it to 65: dowsing simplifies variants toward index 0 and deletes range
items, but does not binary-search a byte toward a threshold, and `n <= 64` is *benign*, so there is
no gradient. Coverage guidance did not shorten discovery for this bug (18 cases with
`NoCoverage` vs 236–692 with sancov): the bug is reached by the very first data frame whose kind is
2, so random exploration finds it almost immediately, and the coverage-guided iterator spends early
cases on novelty instead.

## What works

* Fork-no-exec child, BPF filter with fd-range discrimination, listener handoff via pidfd,
  `SYNC_WAKE_UP`, `ADDFD|SEND` injection at fd 1000+, `CONTINUE` gating, `NOTIF_ID_VALID`.
* Blocking `std::net` client: `connect_timeout` (nonblocking connect + poll + `SO_ERROR`),
  `write_all`, `read_exact`, `set_read_timeout`, `shutdown`, close. `Reset`, `Refused`,
  `TimedOut`, `Unreachable`, EOF and partial data all delivered through the real kernel path.
* tokio current-thread (mio): `EINPROGRESS` connect, epoll readiness on a dup'ed epoll fd found via
  `/proc/<pid>/fdinfo`, timed waits answered by time skips, `tokio::time::timeout` works.
* glibc `getaddrinfo` through synthesized DNS over fake UDP sockets (A/AAAA/NXDOMAIN/SERVFAIL;
  IPv4 and IPv6 fallbacks observed in transcripts). glibc did not reject the reply on this host.
* Server path: `bind`/`listen` answered, `accept`/`accept4` woken with fake connections or
  `ECONNABORTED`, per-connection data gating.
* Coverage across the fork with `ChildCoverage`; panics caught in the child and their message
  reported in the `Verdict`; SIGKILL on timeout.
* `cargo test` (3 tests), `cargo clippy --all-targets` clean; root crate untouched.

## What does not work / limitations

* `select`/`pselect6` are passed through **without gating** (logged as unhandled): a target that
  waits on a fake fd with `select` gets the real socketpair readiness (writable, not readable), so a
  peer event will never be materialised for it.
* `dup`/`dup2`/`dup3` on a fake fd are refused with `EMFILE` (logged): duplicating below fd 1000
  would escape the filter. `SCM_RIGHTS` and `/proc/self/fd` escapes are not handled at all.
* `io_uring_setup` → `ENOSYS`. Netlink (`AF_NETLINK`) sockets are not synthesized; glibc's
  `getaddrinfo` on this host did not need one, but `AI_ADDRCONFIG` resolvers may.
* The DNS reply arrives with an empty source address (AF_UNIX); glibc accepted it here, other
  resolvers (musl, trust-dns/hickory) were not tested. `res_send` retries/timeouts follow the
  target's configuration.
* AF_UNIX vs AF_INET: `SO_RCVBUF`/`SO_SNDBUF` sizes and backpressure differ, `MSG_OOB` is
  unsupported, `SOL_SOCKET` options are `CONTINUE`d onto the socketpair while `IPPROTO_TCP`/`IP`
  options are answered `0` without effect (`getsockopt` reports zeros), `getsockname` returns a
  synthetic local address (`0.0.0.0`/`::` with port `40000 + fd % 20000` until `bind`).
* `sendmsg`/`recvmsg` on stream sockets are `CONTINUE`d without inspecting ancillary data.
* Multi-threaded targets: notifications are served in arrival order; there is no scheduler yet
  (the `variant` hook for "which blocked thread resumes" from the memo is not implemented).
* Coverage is lost when a case is SIGKILLed on timeout; the exit path copies the counters.
* Only x86_64 (`AUDIT_ARCH_X86_64` check in the filter; other arches get `SECCOMP_RET_KILL_PROCESS`).
* Shrinking does not minimise payload values toward the threshold (see above).

## Next steps

1. Gate `select`/`pselect6` (read the fd_set bitmaps with `process_vm_readv`, same path as poll).
2. Scheduler: keep the notification of every blocked thread pending and pick which to answer with
   `rng.variant`; combine with the `time_skips` mechanism into a virtual clock
   (`clock_gettime`/`nanosleep` via vDSO bypass would need `prctl(PR_SET_TSC)`-style tricks or an
   LD_PRELOAD accelerator, so start with syscall-visible waits only).
3. Persistent-child mode: run N cases per fork (reset shared counters, re-`socket()`) to amortise
   the 200 µs fork cost when the target is re-entrant.
4. Value-aware shrinking in dowsing: a `range_item` simplifier that bisects a byte toward the
   smallest still-reproducing value would turn `Compressed[n=225]` into `n=65`.
5. File and time interception with the same filter (`openat` on a path prefix, `clock_gettime`
   through `PR_SET_TSC` is not possible; a vDSO-disabling `LD_PRELOAD` shim is the pragmatic route).
6. Handle `SCM_RIGHTS`/`dup2`-to-low-fd escapes by tracking fake fds per number instead of by range
   (costs one BPF map lookup we cannot do in classic BPF; would need to notify on all `read`/`write`
   and check the fd table in the supervisor, ~2.6 µs per file syscall).
