# dowsing sandbox: deterministic tree search over decisions

Linux x86_64, one machine, no mocks. The target runs as an ordinary process under one
supervisor. The supervisor is the only source of nondeterminism, so a run is a pure function of
the sequence of decisions the supervisor made. A decision sequence is the test case; a prefix of
one is a program state; searching is choosing a state, restoring it, and taking a different
decision there.

## 1. Model

```
Decision   = (kind, choice)           kind ∈ Schedule | Budget | Time | Harness | Syscall
Case       = [Decision]               replayable, shrinkable, the corpus entry
Node       = state reached by a Case prefix, plus the pending decision's choice set
Snapshot   = memory pages + per-thread registers + world model, at a Node
Tree       = root → Nodes, edges labelled by choices; leaves are exits/crashes/deadlocks
```

Decision points, in the order the supervisor sees them:

| kind | when | choice set |
|---|---|---|
| `Schedule` | ≥2 threads runnable | index into runnable threads |
| `Budget` | after a Schedule | exact number of coverage edges before forced preemption; 0 = run to the next natural stop |
| `Time` | nothing runnable, ≥1 timed waiter | which waiter's timeout fires (clock jumps to it) |
| `Harness` | target calls `dowsing::variant(n)` / `range` / raw bytes | `0..n` |
| `Syscall` | emulated syscall with a modelled answer set (later: net/fs/entropy) | model-defined |

Only points with ≥2 choices are decisions; single-choice points are not recorded, so a `Case`
contains exactly the information that matters and shrinking never has to reason about padding.

Invariants that make the run a function of the `Case`:

1. exactly one target thread runs at a time (ptrace stop/resume);
2. the target's clock, entropy, pid/tid and every blocking syscall are answered by the
   supervisor, never the kernel (vDSO hidden at exec, ASLR off, `getrandom` emulated, futex
   emulated, sleeps and timeouts virtual);
3. preemption happens only at instrumented coverage edges (`trace-pc-guard` decrements a shared
   budget; at zero the thread traps to the supervisor), never by timer;
4. kernel-visible state the target can observe is memory + registers only; everything else
   (futex waiters, virtual clock, fd model) is plain data inside the supervisor.

## 2. Interception

One mechanism: a seccomp filter returning `SECCOMP_RET_TRACE` for the modelled syscall set,
`ALLOW` for the rest, plus ptrace (`PTRACE_SEIZE`, `TRACECLONE|TRACEEXIT|TRACESECCOMP|EXITKILL`).
At a seccomp stop the supervisor reads registers, decides, and either lets the syscall through or
skips it (`orig_rax = -1`, `rax = result`). No `LD_PRELOAD`, no seccomp-unotify, no in-process
mode. Measured stop cost ≈ 10 µs; a stop is also a scheduling point, so cost is per decision,
not per syscall.

Traced set today: `futex clone clone3 sched_yield nanosleep clock_nanosleep clock_gettime
gettimeofday time getrandom rseq exit exit_group munmap poll ppoll select pselect6 epoll_wait
epoll_pwait epoll_pwait2 socket epoll_create epoll_create1 eventfd2 sched_getaffinity`, the
harness marker (`getppid(MAGIC, kind, n)`, which is how the target's `dowsing::variant`
reaches the supervisor), and the descriptor family (`read write readv writev recvfrom sendto
recvmsg sendmsg close fcntl ioctl bind listen accept accept4 connect shutdown getsockname
getpeername setsockopt getsockopt epoll_ctl dup dup3 fstat`) *only when `args[0]` is a virtual
descriptor* (`>= 4096`, §9) — the BPF program compares the descriptor, so the target's ordinary
files never stop. `rseq` is refused with `ENOSYS` (per-task kernel state a snapshot cannot
carry); `munmap` is traced for the retention rule in §4; `select`/`pselect6` are traced but not
modelled, so a target using them is *reported* as uncontrolled rather than silently
nondeterministic. The mapping table is read from `/proc/pid/maps` at snapshot time, not
tracked through `mmap`.

## 3. Scheduler and clock

State per thread: `Stopped | Running | FutexWait{addr,val,bitset,deadline} | Exited`.
`futex WAIT/WAKE/*_BITSET` are emulated in the supervisor (waiters are a list, wake order is by
wait sequence). `clone` → both threads `Stopped`, new decision. `exit` → thread removed. When
nothing is runnable: if a `FutexWait` has a deadline, a `Time` decision picks which one fires and
the virtual clock jumps to it; else deadlock, and the run ends with `Outcome::Deadlock`.

Virtual clock `now: u64 ns` lives in the supervisor. `clock_gettime`/`nanosleep`/timed futex
read or advance it; `nanosleep(d)` is a `FutexWait` on a private address with `deadline = now +
d`. The clock never advances while a thread is runnable, so "time passes" only at `Time`
decisions — which is what makes a 120 s backoff cost 0 wall time and stay deterministic.

## 4. Snapshot and restore

A state is `(pages, regs[tid], world)`:

- `pages`: contents of every writable private mapping. Snapshot 0 (root) copies them all.
  Later snapshots copy only pages soft-dirty since the previous snapshot on the path
  (`/proc/pid/clear_refs ← "4"`, then bit 55 of `/proc/pid/pagemap`; unprivileged; measured here:
  scan 2.2 ms per 512 MB, copy via `process_vm_readv` ≈ 1.4 GB/s, restore via `process_vm_writev`
  ≈ 1.1 µs/page).
- `regs[tid]`: `PTRACE_GETREGS` + `GETREGSET(NT_X86_XSTATE)` for every live thread; all are
  stopped.
- `world`: the supervisor's own structs — thread table, futex waiters, clock, mapping table,
  fd model — cloned as data.

Restore to snapshot S from live state L (both on one root-to-leaf path, S an ancestor of L):

1. dirty = pages soft-dirty now ∪ pages copied by every snapshot strictly after S on the path;
2. for each such page, write the newest copy at or before S (walk S's chain; root has all);
3. mapping table: diff L's vs S's; inject `munmap` for mappings L has and S lacks, `mmap` for
   the reverse (syscall injection = set regs, single-step over the `syscall` insn at `rip-2`);
4. threads: those in S and alive get their registers; those alive but not in S are killed by
   injecting `exit`; a thread in S that has since exited makes S **unrestorable** — the tree
   marks S dead and restores from S's nearest live ancestor instead (replaying decisions from
   there, §5). This is the one honest limit of process-level snapshots without a kernel module;
   it costs replay time, never correctness;
5. `world` swapped in, `clear_refs` again, live state now equals S.

Cost is proportional to pages touched between S and L, not to RSS. Fd state is not an issue
because the target holds no observable kernel fd state (§1 inv. 4); stdout/stderr are
append-only and are simply not rewound.

Two things the kernel does that the implementation has to work around:

- Soft-dirty is also a *VMA* flag (`VM_SOFTDIRTY`, set on every new mapping). A new anonymous
  mapping that lands adjacent to an old one — a thread stack below a big table, say — merges
  with it, and from then on `pagemap` reports every page of the merged range dirty — including
  the tens of thousands of never-touched pages of a 8 MB stack. Only *present* pages count as
  dirty (an absent page reads as zero, so it is recorded as zero only if an ancestor snapshot
  held non-zero bytes there, and on restore it is written only if the snapshot holds non-zero
  bytes), and each present dirty page is compared against the copy the parent snapshot already
  holds so that only real changes are kept.
- A run typically frees its setup on the way out (`munmap` of the table when `main` returns).
  Restoring would then have to re-map and rewrite the whole range. Instead `munmap` of memory
  that exists in the current snapshot is turned into `mprotect(PROT_NONE)`: contents stay,
  faults still fault, and restore is one `mprotect` back plus the truly dirty pages. The cost is
  address space, which glibc does not reuse anyway.

## 5. Search

```
loop:
    node   = descend from the root by UCB over children          # reward = new features per run
             until a node with an untried choice
    restore(nearest_snapshot_ancestor(node)); replay(decisions from it to node)
    choice = pick untried choice of node
    run: take choice, then the PCT policy until exit
         every decision point along the way becomes a Node; its coverage delta is recorded
    energy(path) += novelty(edges) + novelty(interleavings)      # new features → hot subtree
    snapshot policy: take one every K decisions on the run
    outcome ∈ {Exit(0), Crash, Panic, Deadlock, Timeout}: non-Exit(0) → failure, Case saved
```

The rollout policy is PCT: each thread gets a random priority, the highest-priority runnable
candidate runs, and at `d ≤ 3` random change points (global edge counts) the running thread is
demoted to the lowest priority. Preemptions already on the prefix count towards `d`, so a rollout
below a forced preemption adds only the remainder. A `Budget` choice is the exact edge distance
to the next change point, so a preemption can land on any instrumented edge; the tree does not
enumerate those. Once a thread has run from a `Budget` node to its natural stop, the guard ids it
executed (from a ring log the target writes next to the bitmap) fix the node's candidates: one
budget per distinct edge of the segment, since preempting at a second execution of the same
edge is not a new program point and a budget past the segment is the same run as 0.

`novelty` has two parts: dowsing's existing feature accounting (new `CoverageId`s) from the
target's shared `trace-pc-guard` bitmap, and *interleaving features* — a context switch
identified by the outgoing thread, its stop point, the last edge it executed and the thread that
ran next. Edge coverage saturates after a few runs on a schedule bug; the interleaving features
are what keep the frontier pointed at unexplored preemption points. Because expansion happens at
decision granularity, restoring to a hot node and taking a sibling choice is exactly "rewind to
the interesting branch"; the snapshot makes the rewind O(pages touched) instead of O(prefix
execution).

Shrinking a failing `Case`: tree-aware `cautious()`. Candidates are (a) delete a decision (later
decisions re-bind by position; the run is re-validated), (b) replace a choice with a smaller
index, (c) truncate. Each candidate shares a prefix with the failing case, so it starts from the
deepest snapshot on that prefix. Same `CaseCost`/feature-count ranking as today.

## 6. dowsing API

The harness is the target. `dowsing::variant(n)`, `range`, `random::<u8>()` in the target
compile to the marker syscall; the supervisor answers from the `Case`. `Case` (bytes + spans)
stays the corpus type: a `Decision` list serialises to it with one span per decision, so
`curious()`/`cautious()`/corpus/dictionary code is unchanged. New public surface:

```rust
pub struct Sandbox { .. }                         // one target binary, one supervisor
impl Sandbox {
    pub fn new(target: impl AsRef<Path>) -> io::Result<Self>;
    pub fn run(&mut self, case: &Case) -> io::Result<Run>;           // replay
    pub fn explore(&mut self, budget: Budget) -> io::Result<Search>; // tree search
    pub fn shrink(&mut self, failing: &Case, budget: Budget) -> io::Result<Case>;
}
pub struct Run { pub outcome: Outcome, pub case: Case, pub decisions: Vec<Decision>,
                 pub coverage: CoverageSet, pub stops: usize, pub wall: Duration }
```

Target side: `dowsing_target::init()` (installs nothing; the runtime attaches to the shared
bitmap fd if present, so the same binary runs natively) and the existing `CaseRng` API routed
through it.

## 7. Layout

```
sandbox/            crate dowsing-sandbox: ptrace, seccomp, supervisor, clock, snapshot, tree, shrink
sandbox/target-rt/  crate dowsing-target-rt: trace-pc-guard callbacks, budget, marker syscall, variant/range
sandbox/targets/    demo programs (built with sancov flags by build-targets.sh; never linked to the fuzzer)
```

Inside `sandbox/src` the crate is layered so that a source of nondeterminism is a module, not
an arm of the supervisor's `match nr`:

```
ptrace, seccomp, shm, snapshot   process control: stops, registers, memory, one BPF program, page store
sched, world, oracle             core state: threads + virtual clock, decisions/trace/coverage, failure classes
model                            the boundary: Model trait, Cx (what a model may do), Emu, Filter, Ext, Prior
models/{time,entropy,net}        built-in models; net/http1 is the first Protocol
session/{mod,events,schedule,snapshot}  the supervisor: lifecycle + dispatch, ptrace/core syscalls,
                                 candidate scheduling and idle, snapshot/restore
tree                             search: PCT rollouts, frontier, replay, shrink
```

A `Model` declares the syscalls it wants stopped (`Filter`: always, or only when `args[0]` is
a virtual descriptor); `seccomp::Program::compose` folds every installed model's filter with
the core's into the single BPF program the child installs. On a stop the session routes the
registers to the owning model, which answers with an `Emu`: return a value, stop the thread at
a schedule point, park it in a `ThreadState::Wait`, pass it to the kernel (reported as
uncontrolled), or let the kernel run it silently. Models also offer external events (`Ext`,
tagged with a `Prior` so the search can rank them without knowing what they are), own their
own decision kinds (`Pending::Model`), and classify idle states (`Model::idle`, folded into
the `Oracle`). Everything a model owns lives in `World` and is cloned with it, so snapshot and
restore need no per-model code. The search sees only `Candidate::{Run, Fire, Ext}` and `Kind`;
nothing in `tree.rs` names a socket.

Everything reused from the spikes is the scheduler's ptrace/seccomp/futex code and the
target runtime. Dropped: seccomp-unotify data plane, fork-based holders, byte-prefix keying,
in-process filters, LD_PRELOAD.

## 8. Milestone 1 (this branch)

Supervisor + scheduler + virtual clock + soft-dirty snapshots + tree search + tree-aware shrink,
on two-thread targets (lost update, deadlock, timeout-dependent bug). Acceptance:

- 100/100 identical traces replaying a `Case` — met (`explore lost_update --replays 100`:
  1 distinct trace hash);
- search finds each bug and reports the `Case`; shrink returns a short `Case` — bugs found
  (with PCT rollouts and the coverage-guided tree: lost update in 3–15 runs, deadlock in 1–53,
  timeout race in 1–10, three seeds each; 10-seed medians 5 / 10.5 / 1.5 in the latest sitting,
  5.5 / 9.5 / 1.5 in the one before; before the tree 60–160 / 20–70 / 2–30);
  shrink returns 5 decisions for the deadlock but 8–12 (3–5 non-default) for the lost update: the
  race needs both threads inside the read/write window and the current shrinker only deletes
  and zeroes decisions, it does not merge adjacent `Budget` preemptions into one. Open;
- restore-from-snapshot measured against re-execution on a target with an expensive prefix
  (`slow_setup`: 64 MB table, ~100 ms to first decision) — replay from snapshot 3.0 ms vs
  ~100 ms fresh, restore 1.6–1.8 ms writing ~18 pages, search 136–262 runs/s (vs 1.5–1.9 ms per
  `fork()` continuation and 35–41 ms per CRIU restore of the same image;
  `sandbox/compare/README.md`); the small targets run at 300–900 runs/s with ~1 ms restores;
- `cargo test`/`clippy` green for the root crate and `sandbox/` — met.

Open: the search is deterministic per seed within one boot of the host (same run-to-failure
repeated, pinned, under load), but between two boots of the same VM some seeds took a different
trajectory on the same binaries (T1 seed 1: run 9 then run 3), i.e. something the target
observes at exec time is host-state dependent and not yet under a model. Replay of a recorded
`Case` is unaffected within a boot; cross-host replay is not yet guaranteed.

Not in milestone 1: net/fs models (they are `Syscall` decisions and a fd model in `world`, slot
already there), parallel supervisors, musl/static targets, signals as decisions.

## 9. Milestone 2: the network is part of the world

Goal: run an unmodified axum/tokio server and find bugs through its socket API. The kernel's
network stack is state the target can observe and a snapshot cannot carry (inv. 4), so it is
replaced, not wrapped: `world.net` owns every descriptor the target gets from `socket`,
`accept`, `epoll_create1`, `eventfd2` and `dup`, and everything those descriptors refer to.

**Descriptors.** Virtual descriptors are numbered from 4096 so the BPF filter can tell them
from the target's real files by one compare on `args[0]`; the kernel never sees them. Objects
(`Socket { Fresh | Listening{backlog} | Connected{client, shut_wr} }`, `Epoll{interests}`,
`EventFd{count}`) are reference counted so `dup`/`dup3`/`F_DUPFD` and close-the-last-one
behave. `epoll_ctl` interests are per descriptor with edge-triggered state (`EPOLLET` arms on
readiness *change*, level reports current readiness); `eventfd` is a counter with `EPOLLIN`
when nonzero — that is all tokio's `mio` waker needs.

**Clients** are the fuzzer's side of each connection: a request byte string, how much of it has
been delivered (`rx`), whether FIN has been sent, and the bytes the server wrote back. They
appear in the tree as decisions:

- `Schedule` candidates now include the net model's events (connect, send to `c`, close `c`)
  next to `Run(t)` and `Fire(timer)`, with PCT priorities of their own (`Prior::Spawn`,
  `Prior::Actor(c)`, `Prior::Last`), so *when* a connection arrives relative to the workers'
  progress is a searched choice;
- `Payload(n)`: which corpus request a new connection carries (`--corpus dir`, one file per
  request; `--request` for literals);
- `Chunk`: how much of the remaining request `Send` delivers — all, half, all but one byte, or
  one byte — so a body split across `read()`s is one decision, not a network accident. A partial
  delivery demotes the client's priority, so the server gets to run on the fragment.

`Close` is only offered after the whole request is delivered (a client that closes early is a
legitimate but different test, and it dominated the early rollouts).

**Blocking.** `read`/`recvfrom`/`accept` on an empty blocking socket, `epoll_wait` with nothing
ready and `poll`/`ppoll` on virtual descriptors park the thread as
`ThreadState::Wait { model: Net, deadline, seq }` with the entry registers saved; a network
change (`deliver`, `connect`, FIN, server write) re-runs the emulation of every parked call and
completes the ones now satisfied;
a deadline is a timer candidate like any `FutexWait` deadline, and firing it completes the call
with the timeout result. So a std server that `poll(fds, 1, 50ms)`s in a loop is a sequence of
`Wait → Fire | Ext(..)` decisions with no wall-clock sleeping. `poll` over kernel
descriptors is left alone when it cannot block (timeout 0) and reported as uncontrolled
otherwise; a mixed set is reported.

**Oracles**, all on the world: a `panicked at` line on the target's stderr (`Outcome::Panic`);
an HTTP status ≥ 500 in a client's response (`Protocol::verdict`, `Outcome::Protocol`); a
client whose request was
fully read but that never got a response once nothing is runnable and the idle timers have been
fired (`Outcome::Hang { clients }`). Repeated equivalent failures (same outcome and first
stderr line) get no novelty credit, so `--keep-going` keeps searching for a *different* one.

**Snapshot/restore** is unchanged: `world.net` is plain data in `World: Clone`, restored with
the rest of the supervisor state; nothing about a connection lives in the kernel.

Measured (`sandbox/compare/README.md`, "axum" section): an unmodified axum 0.8 server on a
2-worker tokio runtime, ~13 000 instrumented edges, runs at 65–105 searches/s with 32-decision
snapshot spacing; the check-then-act lost update across an `await` is found in 5 / 28 / 26 runs
and the split-body 500 in 66 / 8 / 3 runs (three seeds), each replaying with one trace hash.
The same race *without* an await (a few dozen instructions between two uncontended atomics)
is found by one seed in three, after 10 856 runs / 364 s; the other two find nothing in
~14 400 runs / 600 s (native stress finds it in 21–204 rounds): the preemption has to land on
a handful of edges in a syscall-free segment of hundreds to thousands, and the budget fan-out
samples 8 of them per node. That is the next search problem — preempt where the segment
touches shared memory (atomics, lock words), not uniformly — and it is measured here so the
gap is not hidden.
