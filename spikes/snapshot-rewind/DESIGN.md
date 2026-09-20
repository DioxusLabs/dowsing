# Spike `snapshot-rewind`: memory snapshots to rewind and branch execution

Status: design memo, no prototype yet.
Scope: one Linux x86_64 box, no cloud, no KVM/full-VM snapshots.
Base branch: `devin/1789863721-linux-rtld-default`.

## 0. TL;DR

Recommendation: **fork()-based copy-on-write checkpoints taken by the target
process itself, at `range`/`variant` span boundaries, orchestrated by the
existing `curious()`/`cautious()` search loop through a small "checkpoint
server" protocol over socketpairs.** The mechanism is AFL's deferred
forkserver generalised into a *tree* of paused processes: every paused process
is a snapshot of the target at a byte cursor `k` of the RNG stream, and can
spawn any number of continuations for candidates whose first `k` stream bytes
match. Nothing in the harness has to change except adding
`.with_snapshots(policy)` to the builder; the code between `next()` calls keeps
running unchanged, just in a child process.

Why this and not the others (details in §4/§5):

| Mechanism | Snapshot 10 MB / 100 MB / 1 GB | Restore | Restores kernel state? | Unprivileged here? |
|---|---|---|---|---|
| `fork()` COW (recommended) | 0.17 / 1.1 / 4.2 ms (0.07 / 0.34 ms with THP) | free — a continuation *is* a fork; exit+reap 0.17 / 1.2 / 5.9 ms | yes (fds, mmap layout, brk, signal dispositions) — with the fork(2) caveats in §6 | yes |
| ptrace-injected `fork()` in a multithreaded tracee (rr-style) | 1.5–1.8 ms for the injected fork (100 MB–1 GB) + 0.2 ms to seize/interrupt 4 threads | same as fork | yes, but only the calling thread survives; other threads must be re-cloned and their registers/TLS restored | yes (`ptrace_scope=1`, parent→child) |
| Stop-the-world dump via `process_vm_readv` + restore via soft-dirty | 4.9 / 43 / 431 ms (2.2–2.5 GB/s) full dump; soft-dirty reset+scan 0.1 / 0.7 / 10 ms | 1.2 µs per dirty page | **no** (only memory contents; mmap layout, fds, brk, threads must not change) | yes |
| userfaultfd write-protect | register+WP cheap; every first write traps to user space | copy-back of trapped pages | no | **yes despite `unprivileged_userfaultfd=0`**, via `UFFD_USER_MODE_ONLY` |
| CRIU | – | – | mostly | no (not installed; needs caps) |
| KVM / Nyx-style VM snapshot | – | – | everything incl. kernel | `/dev/kvm` exists, not in `kvm` group; out of scope |

Key cost fact for the search loop: a full fork+exit round trip is ~0.3 ms at
10 MB RSS and ~10 ms at 1 GB (≈0.6 ms with transparent huge pages). Snapshotting
therefore only pays when the *prefix* being skipped costs more than that, which
is exactly the "expensive setup phase" case and not the `buggy_stack` case
(whose whole execution is microseconds). The policy in §8 is built around that
inequality.

## 1. What was verified on this machine

Everything below was measured on this VM; numbers are medians of 20 iterations
unless stated otherwise. Throwaway sources (`forkbench.c`, `memdump.c`,
`ptrace_fork.c`, `uffd.c`, `seccomp_notif.c`) were kept out of the repository
on purpose; they are a few dozen lines each and are described in §10 as the
seeds of the prototype's `bench/` directory.

Environment: kernel `6.8.0-1061-aws`, Ubuntu, 8 vCPUs, 31 GB RAM, Rust 1.98.1,
`kernel.yama.ptrace_scope=1`, `vm.unprivileged_userfaultfd=0`,
`kernel.perf_event_paranoid=4`, THP `madvise`, no `criu`,
`/dev/kvm` present but the user is not in `kvm`, `/dev/userfaultfd` is
`crw------- root`. Kernel config: `CONFIG_USERFAULTFD=y`,
`CONFIG_HAVE_ARCH_USERFAULTFD_WP=y`, `CONFIG_PTE_MARKER_UFFD_WP=y`,
`CONFIG_MEM_SOFT_DIRTY=y`, `CONFIG_CHECKPOINT_RESTORE=y`,
`CONFIG_SECCOMP_FILTER=y`, `CONFIG_USER_NS=y` with
`unprivileged_userns_clone=1`.

### 1.1 `fork()` latency vs RSS (private anonymous memory, fully populated)

| RSS | `fork()` median | p90 | child `_exit` + `waitpid` | round trip |
|---|---|---|---|---|
| 10 MB | 0.165 ms | 0.20 ms | 0.17 ms | 0.34 ms |
| 100 MB | 1.13 ms | 1.21 ms | 1.24 ms | 2.37 ms |
| 1000 MB | 4.17 ms | 5.85 ms | 5.86 ms | 10.1 ms |
| 100 MB, `MADV_HUGEPAGE` | 0.072 ms | 0.084 ms | 0.065 ms | 0.14 ms |
| 1000 MB, `MADV_HUGEPAGE` | 0.34 ms | 0.46 ms | 0.22 ms | 0.56 ms |
| 100 MB, `MAP_SHARED` | 0.033 ms | – | 0.05 ms | 0.085 ms |
| 1000 MB, `MAP_SHARED` | 0.037 ms | – | 0.05 ms | 0.091 ms |

Observations:

* `fork()` is linear in the number of PTEs to copy (~16 ns/PTE; 1 GB = 262 k
  PTEs ≈ 4 ms). Tearing the child down costs about the same again, so the
  per-continuation overhead is ≈ 2× the fork time.
* THP (`madvise(MADV_HUGEPAGE)` on the big allocations) cuts both by ~10×.
  A prototype should allocate its "expensive state" with huge pages where
  possible, or at least measure with and without.
* `MAP_SHARED` memory is not copied at all (constant 35 µs) — but it is also not
  snapshotted, since writes are visible to all processes. This is the right
  mapping for *coverage counters and IPC*, and the wrong one for target state.
* COW faults in the continuation cost ~2 µs/page: a child that dirties 100 k
  pages (400 MB) of a 1 GB parent takes 210 ms from fork to reaped (COW
  faults + freeing the copies), versus 6 ms when it dirties nothing. Continuations that rewrite most of the state
  gain little from snapshots.

### 1.2 ptrace-injected `fork()` in a multithreaded child (rr-style)

`PTRACE_SEIZE` + `PTRACE_INTERRUPT` of all threads of a 4-thread, 100 MB child:
0.20 ms to reach a stopped state for all threads. Injecting `fork()` into one
stopped thread (save regs, overwrite the two bytes at `rip` with `syscall`,
set `rax=57`, `orig_rax=-1`, `PTRACE_SINGLESTEP`, catch `PTRACE_EVENT_FORK`,
restore code and regs) returned a live grandchild after **1.77 ms** (100 MB,
4 threads) and **1.49 ms** (1 GB, 1 thread). As fork(2) documents, the
grandchild has exactly one thread; the other threads must be recreated with an
injected `clone(CLONE_VM|CLONE_FS|CLONE_SIGHAND|CLONE_SYSVSEM)` in the new
process and their registers, FS base (TLS) and XSTATE copied over — this is
precisely what rr does in `Task::os_fork_into` / `Task::os_clone_into` /
`copy_state` (rr `src/Task.cc`). Being stopped in a syscall
(`orig_rax=230`, `clock_nanosleep`, in our run) is the normal case and needs
the syscall-restart handling rr has. Feasible, but it is a second-phase item
(§9) because it only becomes *correct* once the fuzzer schedules threads
deterministically (the sibling `deterministic-scheduler` spike): a thread
blocked in `futex_wait` inside the kernel has state that no user-space copy
can reconstruct.

### 1.3 Stop-the-world dump/restore via `process_vm_readv/writev` + soft-dirty

| RSS | full dump (`process_vm_readv`) | `clear_refs`=4 | `pagemap` scan | restore 1000 dirty pages |
|---|---|---|---|---|
| 10 MB | 4.9 ms (2.2 GB/s) | 0.09 ms | 0.04 ms | 0.12 ms (100 pages) |
| 100 MB | 43 ms (2.4 GB/s) | 0.37 ms | 0.31 ms | 1.2 ms |
| 1000 MB | 431 ms (2.4 GB/s) | 4–5.6 ms | 4–5 ms | 1.5 ms |
| 1000 MB, 100 k dirty | 431 ms | 4.4 ms | 4.1 ms | 119 ms (1.2 µs/page, one `writev` per page) |

Soft-dirty tracking works unprivileged (`/proc/pid/clear_refs` is writable by
the owner; bit 55 of `/proc/pid/pagemap` is readable by the owner, only PFNs are
hidden). The kernel's `PAGEMAP_SCAN` ioctl (6.7+) is not in this distro's
`linux/fs.h`; it would avoid reading 8 bytes/page but is an optimisation only.
Restore throughput would improve with batched iovecs (up to 1024 per call).
This mechanism restores *memory only*; `brk`/`mmap` growth, fds, threads,
signal state are untouched. It is a good *in-place reset* for a persistent-mode
loop whose address-space layout is stable, and a poor general snapshot. Kept as
an optional optimisation (§5.3).

### 1.4 userfaultfd

`userfaultfd(0)` → `EPERM`; `open("/dev/userfaultfd")` → `EACCES` (mode 0600
root). But `userfaultfd(UFFD_USER_MODE_ONLY)` **succeeds** unprivileged
(`unprivileged_userfaultfd=0` only forbids handling kernel-originated faults;
`Documentation/admin-guide/sysctl/vm.rst` (v6.8): "users without
CAP_SYS_PTRACE must pass UFFD_USER_MODE_ONLY in order for userfaultfd to
succeed" — verified here). API features
reported `0x1ffff` including `UFFD_FEATURE_WP_ASYNC` and
`PAGEFAULT_FLAG_WP`; `UFFDIO_REGISTER` in WP mode on anonymous memory and
`UFFDIO_WRITEPROTECT` both succeed. So write-protect dirty tracking is
available unprivileged on this box. It still cannot restore anything by itself
and each first write to a page costs a trap+handoff; soft-dirty gives the same
dirty set for far less mechanism. Not recommended for this spike; noted as a
fallback if `clear_refs` ever gets restricted.

### 1.5 seccomp user notification and ptrace of children

`seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER)` works
unprivileged after `PR_SET_NO_NEW_PRIVS`; a supervisor in the parent answered
`getppid()` from the child in **8.7 µs per round trip**. This matters to this
spike only as the future channel through which a continuation's syscalls
(time, entropy, files, network) are answered deterministically (the sibling
`sandbox` spike); it also proves the parent-supervises-child topology we rely
on is permitted. `PTRACE_SEIZE` of a direct child works under
`ptrace_scope=1`.

### 1.6 Dowsing facts the design depends on (from reading the crate)

* An execution is a pure function of the **byte stream** the harness draws.
  `CaseRng::next_byte` (`src/iter/rng.rs`) serves `prefix[cursor]` while the
  cursor is inside the prefix, then zeros (`zero_tail`, cautious mode) or bytes
  from `fallback = SmallRng::seed_from_u64(seed)`. The seed does *not* influence
  bytes inside the prefix. Hence two candidates with the same first `k` stream
  bytes reach the same target state after `k` bytes (given a deterministic
  target), regardless of seed, `zero_tail`, origin or mutation. The stream can
  be materialised without running the target, so "does snapshot at `k` apply to
  candidate `c`" is a cheap byte comparison.
* Structure is recorded as `DrawSpan`s (every draw), `SemanticSpan`s
  (`Length`, `Item`, `Variant`) and `SequenceSpan`s (a `range` with its length
  draw and item spans), all as byte offsets into the trace, capped at
  `MAX_PREFIX_LEN = 4096`. `cautious()`'s 15 reducer passes (`src/iter/shrink.rs`)
  operate on these spans; `SequenceDelete`, `SemanticDelete`,
  `SemanticSimplify`, `SequenceProject/Replace`, `TailTrim`, `BlockZero`, ...
  all leave bytes *before* the edited span untouched.
* `curious()` mutates a parent prefix (`mutate_prefix`, depth
  `mutate_depth`) and gives the child a new seed
  (`parent_seed ^ fallback.rotate_left(17)`); with `MAX_PREFIX_LEN`-sized
  prefixes most mutations keep a long common literal prefix with the parent.
* Coverage: `SancovCoverage` inline 8-bit counters and `LlvmCoverage`
  `-Cinstrument-coverage` counters are plain process memory;
  `finish_capture` reads them. trace-pc-guard mode records per-thread guard
  hits. `ParallelCoverageCapture` exists because inline counters are
  process-global — a limitation that forking sidesteps (§7).
* `State` (`src/iter/prelude.rs`) keeps the corpus with energy from feature
  rarity (`corpus_energy`), pending cases, cautious reducer state; the search
  loop (`src/iter/run.rs`) already separates *planning* a candidate
  (`choose_candidate_plan` → `CandidatePlan` → `materialize_candidate`) from
  *running* it. The snapshot dispatcher slots in between.

## 2. Problem statement, restated in dowsing terms

Today every candidate re-executes the target from byte 0. For targets with an
expensive setup (build a large in-memory model, parse a corpus, replay a WAL,
warm caches) or long stateful prefixes, most of the wall time is spent
recomputing a state the search has already visited. We want: given a corpus
entry `P` with trace `T`, and a candidate `c` whose stream agrees with `T` on
the first `k` bytes, resume the target from the state it had at cursor `k`
and only execute the tail. Equivalently: turn the search over RNG prefixes into
tree search where inner nodes are live process states.

Non-goals for this spike: multithreaded targets (phase 2, §9), intercepting
syscalls (sandbox spike), deterministic thread scheduling (scheduler spike),
cross-machine anything.

## 3. Recommended approach: a tree of forked checkpoint holders

### 3.1 Process topology

```
P  (harness process; owns State, corpus, reducer; runs the for-loop)
└─ R0 (runner for candidate c0: forked by P inside `next()`)
   ├─ at span boundary k1: fork → H1 (holder, paused at k1) ; R0 continues
   │      H1 ── on request "run tail for c" ──▶ R(c) (continuation, cursor=k1)
   │      H1 ── ... ──▶ R(c')                          ┐ any number, in parallel
   │                                                    ┘
   └─ at span boundary k2: fork → H2 ; R0 continues, finishes, reports, _exit
```

* **P** never executes target code for a candidate; it forks a runner and
  waits for its report (AFL forkserver shape, but the forkserver logic lives in
  `Curious::next()`/`Cautious::next()` so the user's `for mut rng in curious()`
  loop is unchanged). The body of the loop runs in R0. When R0 calls `next()`
  again (or drops the rng, or panics), `next()` recognises it is a runner,
  ships its report to P, and `_exit(0)`s. The loop only ever advances in P.
* **Holders** are created by the runner itself when `CaseRng` crosses a span
  boundary that the policy (§8) has marked as a checkpoint: `fork()`; the
  *child* continues as the runner (so it inherits the runner's socket to P),
  the *parent* becomes the holder. Before forking, the runner creates a fresh
  `socketpair`, sends one end to P over its report socket with `SCM_RIGHTS`
  together with `{k, hash(T[..k]), spans so far, wall time so far}`, and the
  holder blocks reading the other end. P thus holds one control fd per
  snapshot.
* **Continuation**: P writes `{seed, prefix, zero_tail, origin, k, new report
  socket}` to a holder. The holder forks; the child installs the candidate's
  RNG state (`prefix`, `seed`, reseeded `fallback` advanced by
  `max(0, k - prefix.len())` bytes, `zero_tail`), keeps `cursor = k` and the
  trace/spans it already has, and continues executing exactly where the holder
  was paused — inside `next_byte()` of the draw that started the span. The
  holder loops back to `read()`.
* Continuations of one holder are independent processes, so P can run several
  concurrently (bounded by a `parallelism` knob). This gives parallel
  exploration without `ParallelCases`/`rayon` and without the trace-pc-guard
  requirement (§7).
* Cleanup: every child sets `prctl(PR_SET_PDEATHSIG, SIGKILL)` against P and P
  reaps with `pidfd`s (`pidfd_open`, poll for exit) so a dying P never leaks a
  holder tree; holders are killed by P when evicted (§8.4).

### 3.2 Why this shape

* It is the only mechanism in the table that restores *kernel-visible* process
  state — fd table, `mmap` layout, `brk`, signal dispositions, `rseq`,
  `set_robust_list` — for free, because the kernel makes the copy.
* Snapshot cost is paid once per holder and is independent of how many
  continuations it serves; the marginal cost of a continuation is one
  `fork` + one `_exit` (0.3 ms – 10 ms depending on RSS, or ~0.15–0.6 ms with
  THP). With soft-dirty in-place reset (§5.3) this can drop further for hot
  holders.
* It keeps dowsing's contract intact: a `Case` is still `seed + prefix + spans`,
  fully replayable without any snapshot. Snapshots are a *cache*, never part of
  the persisted state, so a corrupted/expired holder degrades to "run from
  byte 0" — this is the same fallback we need anyway when a candidate has no
  matching snapshot.
* It composes with the other spikes: a holder is a paused process, so the
  future syscall sandbox (seccomp-notif) and deterministic scheduler
  (ptrace/`SIGSTOP` per thread) just see one more child.
* rr's checkpoints (`ReplaySession::clone`) and libAFL's
  `InProcessForkExecutor` are the same idea at different granularities; AFL++'s
  deferred forkserver (`__AFL_INIT()` after setup) is exactly the single
  holder case. Antithesis is the same tree-of-timelines idea one level down
  (hypervisor snapshots), which is why the out-of-scope KVM path is a natural
  later swap-in behind the same P↔holder protocol.

### 3.3 Correctness conditions (what the target must satisfy)

1. Deterministic w.r.t. the byte stream up to `k`: no wall-clock, entropy,
   thread timing, or address-dependent (`HashMap` with `RandomState`, pointer
   hashing) behaviour on the path to the checkpoint. ASLR is not a problem —
   fork preserves addresses — but hashing pointers still makes *replay from
   byte 0* differ from *continuation from a holder*. This is already a
   requirement for `Case` replay; snapshots just make violations visible
   sooner. The prototype should include a "replay check" mode that re-runs a
   sample of continuations from byte 0 and asserts identical coverage
   (`curious()` already has `discard()` for non-reproducing candidates).
2. Single-threaded at checkpoint time (phase 1). `fork()` copies only the
   calling thread; a holder with live helper threads (rayon pools, tokio
   workers) would spawn continuations missing them. The runner should refuse to checkpoint if
   `/proc/self/status` `Threads:` > 1 (cheap read at boundary time) and log it.
3. No process-external side effects before the checkpoint that continuations
   would repeat or share: buffered stdout must be flushed before forking (the
   runner does `libc::fflush(NULL)` and `std::io::stdout().flush()`), open
   files are shared by offset (§6).
4. Memory: a holder costs its page tables (2 MB per GB of 4 K pages) plus any
   pages it dirties (none, it is paused). Continuations pay COW per dirtied
   page (~2 µs). Total live memory is bounded by the policy's holder budget.

## 4. Alternatives considered and rejected (for phase 1)

### 4.1 Stop-the-world dump/restore via `/proc/pid/mem`/`process_vm_readv`

Rejected as the primary mechanism: a full dump is 100× slower than `fork()`
(431 ms vs 4 ms at 1 GB) and, more fundamentally, restoring bytes into an
existing process only works if nothing else changed — no `mmap`/`munmap`,
no `brk` growth, no fds opened/closed, no thread created, no `sigaltstack`,
no `rseq`/robust-futex registration. Rust allocators do grow the heap; any
target that allocates past its high-water mark between snapshot and restore
breaks the invariant, and detecting that requires diffing `/proc/pid/maps`
every time. Kept only as an optional in-place *reset* optimisation (§5.3).

### 4.2 userfaultfd

Works unprivileged via `UFFD_USER_MODE_ONLY` (§1.4) — a useful correction to
the assumption that `unprivileged_userfaultfd=0` blocks it — but it is a dirty
*tracking* primitive, not a snapshot primitive: it tells us which pages changed
(soft-dirty does the same with zero per-fault cost) and can supply pages on
demand (useful for lazy restore of a huge dump, which we do not want to do).
Also, `UFFD_USER_MODE_ONLY` means any *kernel*-originated access to a
protected page (e.g. `read(2)` into a buffer, `process_vm_writev` from P)
delivers `SIGBUS` to the target — a real footgun for a fuzzer that also
intercepts syscalls. Rejected for this spike.

### 4.3 CRIU

Not installed; needs `CAP_CHECKPOINT_RESTORE`/`CAP_SYS_ADMIN` for full
functionality; designed for whole-process-tree save/restore to disk with
~100 ms-second latencies. Wrong tool for millisecond-scale branching.

### 4.4 Full-VM snapshots (KVM, Nyx/kAFL style)

`/dev/kvm` exists but the user lacks group access, and it is explicitly out of
scope. It is the only route that captures kernel state (socket buffers, futex
waiters, page cache) and would make §6 moot; Nyx's incremental snapshots via
dirty-page logging are the gold standard for speed at scale. Noted as the
future replacement for the *holder* implementation behind the same P↔holder
protocol: "snapshot handle + run tail bytes → report" is agnostic to whether
the handle is a paused process or a VM snapshot.

### 4.5 In-process checkpoints (`setjmp`-style state copy, arena reset)

Copying the target's heap by hand or requiring the target to implement
`Clone`/`reset()` reintroduces mocking-by-another-name and cannot capture
fds or stack state. Rejected as incompatible with the "nothing has to be
mocked" vision, though a `CaseRng::checkpoint()` *hint* API (§8.5) lets a
harness say "this is a good place" without implementing anything.

### 4.6 ptrace-injected fork as the phase-1 mechanism

Measured feasible (§1.2) but strictly more machinery than in-runner
`fork()` for single-threaded targets: it needs a supervisor thread in P
tracing every runner (each ptrace stop is a context switch; syscall-heavy
setup would slow down), code patching at `rip`, syscall-restart handling, and
`PTRACE_O_TRACEFORK` bookkeeping. Its one advantage — snapshotting a process
that did not cooperate — only matters for multithreaded targets, where it is
also insufficient without deterministic scheduling. Deferred to phase 2 (§9).

## 5. Design details

### 5.1 Wire protocol (P ↔ runner/holder), all over `AF_UNIX` `SOCK_SEQPACKET`

Messages are tiny, fixed-layout, little-endian; no serde dependency needed
(the crate currently depends only on `rand` and `rayon`; the prototype adds
`libc`).

Runner → P:
* `Checkpoint { k: u32, trace_hash: u64, elapsed_ns: u64, spans_delta: ... }`
  + `SCM_RIGHTS(holder_ctl_fd)`.
* `Report { outcome: Finished | Discarded | Panicked | Killed, cost: CaseCost?,
  trace_len: u32, trace: [u8], draws/semantics/sequences: [...],
  feedback: ExecutionFeedback { features: [u64], hit_count_weight: u64,
  dictionary: [[u8]] } }`. Length-prefixed vectors; `features` are
  `CoverageId`s already computed *in the runner* by
  `Capture::finish_capture`, so any `CoverageCapture` whose state lives in
  process memory works unchanged (Sancov counters, `LlvmCoverage`, custom).
* `Interesting { case: Case }` when the harness calls `fork_case()` (so P can
  seed `pending_cases`, mirroring what `fork_case()` + `with_case()` do today).

P → holder:
* `Spawn { seed: u64, zero_tail: bool, origin: u8, k: u32, prefix: [u8] }`
  + `SCM_RIGHTS(report_fd)`; holder replies `Spawned { pid }` on the same
  control socket so P can `pidfd_open` it.
* `Retire` → holder `_exit(0)`.

Panics: the runner installs a panic hook that, before unwinding, writes a
`Report { outcome: Panicked, trace, spans, feedback }` so the case *and* its
coverage are not lost; P treats it as a failing case (today a panic in the
harness aborts the whole loop — with runners it becomes a finding). Signals
(`SIGSEGV`, `SIGABRT`, OOM) are seen by P as `Killed` via `waitid`, with the
trace reconstructed by replaying the candidate from byte 0 in a fresh runner
with `RUST_BACKTRACE` etc. — the same job `discard()`/reproduction does now.

### 5.2 Snapshot index in P

```
struct SnapshotTree {
    // trie over stream bytes; a node is a holder if `holder.is_some()`
    nodes: Vec<Node>,             // Node { children: SmallMap<u8, NodeId>, holder: Option<Holder>, depth: u32 }
    holders: Slab<Holder>,        // Holder { ctl: OwnedFd, pid: Pid, k: u32, rss_kb: u64, created: Instant,
                                  //          prefix_cost: Duration, hits: u32, last_used: Instant,
                                  //          root_case: CorpusId, span_kind: SemanticKind }
    budget: SnapshotBudget,       // max holders, max total rss, max age
}
fn best_holder(&self, stream: impl Fn(usize) -> u8 /* materialised candidate bytes */) -> Option<HolderId>
```

`best_holder` walks the trie along the candidate's materialised stream and
returns the deepest holder; P then sends `Spawn` there, or forks a fresh root
runner if none. Materialising a candidate stream is `prefix` followed by
`SmallRng::seed_from_u64(seed)` bytes or zeros — no target code runs.

### 5.3 Optional: in-place reset of a hot holder (soft-dirty)

For a holder that serves many short continuations, `fork` + `_exit` per
continuation (~0.3–10 ms) can be replaced by *reusing one* continuation
process: P forks one continuation from the holder and ptrace-seizes it, records
its memory image once (`process_vm_readv` of all writable private mappings,
43 ms per 100 MB, paid once per reused process), writes `4` to its
`clear_refs`, lets it run a tail, then instead of letting it exit: reads its
`pagemap` soft-dirty bits (0.3 ms per 100 MB), writes the dirty pages back
from the image (1.2 µs/page), resets registers with `PTRACE_SETREGSET` to the
values captured at the resume point, clears soft-dirty again and lets it run
the next tail. This requires the continuation to be ptrace-stopped at the
same `rip` and to have an unchanged `/proc/pid/maps`; on any `maps` change or
after `N` reuses it is killed and replaced by a normal fork. This is the
AFL-Snapshot-LKM idea in user space with soft-dirty instead of a kernel module.
Not in the phase-1 prototype; it is the first optimisation to measure after the
baseline exists, because for `buggy_stack`-sized tails it would be the
difference between "snapshots help" and "snapshots are pure overhead".

### 5.4 Lifetime and reaping

* Root runners: one per candidate; exit after `Report`.
* Holders: live until evicted (§8.4), P exits, or their root corpus entry is
  dropped from the corpus (P sends `Retire`).
* P registers an `atexit`/`Drop` on `Curious`/`Cautious` that retires all
  holders and reaps; `PR_SET_PDEATHSIG` covers P crashing.
* `SIGCHLD` is not used (harnesses may have their own); P polls `pidfd`s.

## 6. File descriptors and other state: what is and is not restored

fork(2) (man7, read for this memo) is the spec. Honest summary for a
continuation spawned from a holder:

Restored exactly (because it is process memory or per-process kernel state
copied by fork): heap, stacks, globals, mmap layout, `brk`, TLS, signal
dispositions and mask, `sigaltstack`, the fd *table* (numbers → open file
descriptions), cwd/umask, `rseq`/robust-list registrations, seccomp filters
(inherited), coverage counters (memory).

**Shared, not copied** (the child's fd points at the *same open file
description*): file offsets, `O_NONBLOCK`/`O_APPEND` flags, `F_SETOWN`. Two
continuations reading the same fd race on the offset and steal each other's
data; the holder's offset moves too. Mitigation in phase 1: at checkpoint,
the runner records `/proc/self/fdinfo/*` (`pos`, `flags`) and the continuation
re-`lseek`s regular files to the recorded offsets on resume (cheap, correct for
regular files opened read-only or for files the tail only reads). Files
written by continuations (logs, temp files) are *not* isolated — writes
interleave. Recommend the prototype target not write files after the first
checkpoint, and that the sandbox spike virtualises files in a later phase
(seccomp-notif answering `openat`/`read`/`write` with fuzzer-owned buffers
makes this problem disappear because file state becomes target memory).

**Cannot be restored** at all with any process-level mechanism:
* Sockets, pipes, ttys, `eventfd`, `timerfd`, `epoll` instances: the kernel
  object is shared; bytes consumed by one continuation are gone for its
  siblings; a TCP peer sees one interleaved stream. Only a VM snapshot or
  virtualising the fd (sandbox spike) fixes this. Phase 1 refuses to
  checkpoint if the runner has any fd whose `/proc/self/fd` link is
  `socket:`/`pipe:`/`anon_inode:` other than the runner's own report socket,
  and reports the reason (policy flag `allow_shared_fds` to override).
* Pending signals, POSIX timers/`setitimer`, `alarm`, `aio`, `io_uring`,
  memory locks, record locks (`fcntl(F_SETLK)` are per-process and *dropped*
  in the child; `flock` and OFD locks are inherited/shared).
* Other threads and everything only they own (their stacks exist in memory but
  no task executes them; mutexes they held stay locked forever).
* Kernel-side state of the *holder* itself keeps evolving only if the holder
  runs code; it does not, so a holder is stable, but its `Checkpoint`'s fds are
  still shared with every continuation.
* Anything outside the process: databases, files on disk written before the
  checkpoint (fine, they are stable) or after (not isolated), external
  services, the terminal.

The memo's position: phase 1 is for targets whose state is in memory plus
read-only files, which is the class of tests dowsing serves today; the sandbox
spike is what makes network/file-writing targets snapshot-safe, and the
`Checkpoint` refusal rules make the boundary explicit instead of silently
wrong.

## 7. Coverage attribution across snapshots

* Inline 8-bit counters (`SancovCoverage` default) and `LlvmCoverage` counters
  are memory: a holder's copy contains the prefix's hits; every continuation
  adds its tail's hits to *its own copy* and `finish_capture` in the runner
  produces feedback for the whole path `T[..k] ++ tail`. Attribution is exact
  and there is no cross-talk between concurrent continuations — the process
  boundary is the isolation `ParallelCoverageCapture` currently demands
  trace-pc-guard for. `start_capture` is called once in the root runner
  before user code runs (as `ensure_started` does today) and *never again* in
  continuations; `CaptureGuard`/`CAPTURE_LOCK` state is inherited as memory.
* trace-pc-guard mode records into thread-locals; fork copies the calling
  thread's TLS, so it also works unchanged.
* `ExecutionFeedback` (`features`, `hit_count_weight`, `dictionary`) is
  serialised to P; P calls the same code path `coverage()` uses after
  `finish_capture` (record into `State`, update corpus energy, dictionary).
  `CoverageCapture` needs no new required method; a provided
  `fn feedback_is_process_local(&self) -> bool { true }` lets an exotic backend
  (e.g. one talking to an external collector) opt out of snapshots.
* Prefix-only feedback: at `Checkpoint` time the runner *also* sends the
  feedback of `T[..k]` (a non-destructive read of the counters — `finish_capture`
  is destructive in some backends; add `peek_capture` as a provided method
  defaulting to "unsupported → don't send"). P uses it to attribute rare
  features to the prefix vs tail, which feeds the policy (§8.2): a holder whose
  prefix already contains the rare features that give its corpus entry its
  energy is a better branch point than one before them.

## 8. Where to snapshot: policy proposal

### 8.1 Candidate points

Only span boundaries, never arbitrary bytes:

* the start of each **top-level `range` item** (`SemanticKind::Item` whose
  `SequenceSpan` has no enclosing sequence);
* the start of each **`variant`** draw (`SemanticKind::Variant`);
* the byte right after a **cost cliff**: at each span boundary the runner
  reads `Instant::now()` (one `clock_gettime`, ~20 ns via vDSO; only at
  boundaries, not per draw); if the elapsed time since the previous boundary
  exceeds `policy.cliff` (default 1 ms), the *next* boundary is a candidate
  regardless of energy. This is what finds "after the expensive setup".

Aligning with spans is what makes `cautious()` reuse snapshots: every reducer
pass edits within or after a span, so a snapshot at the span's start byte
remains valid for every reduction of that span or later spans. It also
guarantees the continuation resumes at a draw boundary, so the tail's
`DrawSpan`s line up with the candidate's byte offsets.

### 8.2 When a candidate point becomes a holder

A point at cursor `k` of corpus entry `E` is worth a holder when

```
expected_reuse(E, k) × prefix_cost(E, k)  >  snapshot_cost(rss) + expected_reuse × continuation_overhead(rss)
```

* `prefix_cost(E, k)` — wall time from start to the boundary (runner reports
  `elapsed_ns` in `Checkpoint`; stored per boundary in `CorpusSeed` as a
  small `Vec<(k, ns)>`).
* `snapshot_cost(rss)`, `continuation_overhead(rss)` — measured at startup by a
  calibration fork of the root runner (or the table in §1.1 as a prior:
  ~4.2 µs/MB fork, ~6 µs/MB exit at 4 K pages; ~0.4 µs/MB with THP).
* `expected_reuse(E, k)` —
  * *curious*: the number of mutations P intends to schedule for `E` that
    keep `T[..k]`. `choose_candidate_plan` picks parents by energy
    (`corpus_energy`, rare-feature based), so use
    `energy_share(E) × mutations_per_round × P(mutation preserves k bytes)`;
    the last factor is empirical from `mutate_prefix` (measure once: fraction of
    mutations with LCP ≥ k for `k` at 25/50/75 % of the prefix). Prefer `k`
    just *after* the last rare feature of `E` (from §7 prefix feedback):
    branching there explores continuations that already own the rare
    coverage.
  * *cautious*: exactly computable. The reducer state
    (`next_cautious_reduction`) enumerates upcoming candidates; for the
    current best case, count pending reductions whose first edited byte is
    ≥ k. `SequenceDelete` over an n-item top-level range yields ≈ n
    candidates sharing the prefix up to the deleted item; `TailTrim`,
    `BlockZero`, `WordLower`, `ByteLower`, `RepeatedValue`,
    `DictionaryRepair` all share the prefix up to their edit point. Snapshot
    at the item boundaries with the most pending edits at or after them; for a
    linear pass this is a handful of holders spread along the case.

### 8.3 How many

Bounded: `max_holders` (default 32), `max_holder_rss` (default 25 % of
`MemAvailable`; holders are paused so their real cost is page tables + the
COW pages later dirtied by *continuations*, which are transient), one holder
per `(E, k)`; per corpus entry at most `max_per_case` (default 4) chosen
greedily by the inequality above with the extra rule that consecutive holders
in one execution must be at least `min_gap` apart in `prefix_cost` (default
2× `snapshot_cost`) so we do not fork every 100 µs.

### 8.4 Eviction

Score = `hits_recent × prefix_cost / rss`; evict the lowest when over budget,
also evict when the root entry leaves the corpus, when `curious()` stops
scheduling the entry (energy below threshold for `N` rounds), or when a
holder is older than `max_age` (default 60 s) without hits. Cautious mode
evicts all holders of the previous best case when a strictly better case is
adopted, except those whose `k` is still a valid prefix of the new best.

### 8.5 Harness hints

* `CaseRng::checkpoint_hint()` — a zero-byte marker (recorded as a
  `SemanticKind::Checkpoint` span of length 0 — no bytes consumed, so cases
  stay compatible) telling the policy "prefer here"; the policy still applies
  the budget. Typical use: right after building the expensive model.
* `Curious::with_snapshots(SnapshotPolicy)` / `Cautious::with_snapshots(..)`
  to enable; default off (the crate stays single-process by default so
  `cargo test` behaviour is unchanged).
* `SnapshotPolicy::only_hinted()` for harnesses that want full control.

### 8.6 What should be `range`/`variant` spans so `cautious()` can shrink and snapshots align

Rule for harness authors (and for the demo target): every decision that
changes *what state is built* must be a span, not a raw `gen()`:

* the setup's size/shape parameters (`n_records`, `n_shards`, seed of the
  synthetic dataset) — one `range(..)` of setup items or explicit `variant`s,
  so `SemanticLength`/`SemanticSimplify` can shrink the expensive part and the
  first snapshot lands right after it;
* the operation sequence — a top-level `range(0..N)` whose items are
  `variant(n_ops)` followed by that op's arguments (as `buggy_stack` does
  implicitly today with `gen::<u8>() % 7`; making it `rng.variant(7)` records
  the `Variant` span, which both enables `SemanticSimplify` and makes each op
  boundary a candidate checkpoint);
* per-op payloads as nested `range`s (byte strings, lists) so
  `SequenceDelete`/`SequenceProject` work within an op without invalidating
  the snapshot before it;
* anything that selects an *environment* behaviour once the sandbox exists
  (fault injection choices, scheduler picks) as `variant`s at the point of the
  decision — these are exactly the branches worth rewinding to.

## 9. Phase 2 outline (not in this prototype): multithreaded targets

* Mechanism: rr-style. P (or a supervisor thread in P) `PTRACE_SEIZE`s each
  runner at spawn (`PTRACE_O_TRACECLONE|TRACEFORK|EXITKILL`); the scheduler
  spike's per-thread `PTRACE_INTERRUPT`/`PTRACE_CONT` already places every
  thread at a known stop (syscall entry or a scheduler point). At a checkpoint
  P injects `fork()` into the leader (1.5–1.8 ms measured), then for each other
  thread injects `clone(CLONE_VM|CLONE_FS|CLONE_SIGHAND|CLONE_SYSVSEM)` in the
  child, copies `NT_PRSTATUS`, `NT_X86_XSTATE`, FS/GS base, `set_tid_address`,
  `set_robust_list`, `rseq`, `sigaltstack` (rr `copy_state`), and rewinds
  threads stopped in interrupted syscalls to the syscall instruction with
  `-ERESTARTSYS` semantics. Threads blocked in `futex_wait` must be restarted
  from user space (the wait is re-issued; correctness requires the
  deterministic scheduler to replay the wake order).
* Alternative to explore: use `clone3(CLONE_INTO_CGROUP)`-era APIs? No help.
  `vfork`/`CLONE_VM` in the *holder* to avoid copying page tables: not
  applicable, we need the copy.
* Everything else (protocol, index, policy, coverage) stays.

## 10. Prototype plan

All new code under `spikes/snapshot-rewind/` first (a separate crate in the
workspace, `dowsing-snapshot-spike`, depending on the root crate by path) so
the base crate's `cargo test`/`clippy` stay green; graduate into `src/` only
once the demo numbers justify it.

### 10.1 Files

```
spikes/snapshot-rewind/
  DESIGN.md                      (this memo; update with measured results)
  Cargo.toml                     (deps: iterator-fuzz = { path = "../.." }, libc, rand)
  bench/
    forkbench.c                  fork latency vs RSS (+THP, +shared)           [exists as throwaway]
    memdump.c                    process_vm_readv/writev + soft-dirty            [exists]
    ptrace_fork.c                seize/interrupt/inject fork, thread count        [exists]
    uffd.c                       USER_MODE_ONLY + WP probe                        [exists]
    seccomp_notif.c              user-notif round trip                            [exists]
    run.sh                       builds all, prints the tables in §1
  src/
    proto.rs                     message encode/decode, SCM_RIGHTS helpers (libc sendmsg/recvmsg)
    runner.rs                    runner side: fork-at-boundary, holder loop, panic hook, fdinfo capture
    tree.rs                      SnapshotTree, best_holder, budget/eviction
    policy.rs                    SnapshotPolicy, cost model, expected_reuse for curious/cautious
    supervisor.rs                P side: spawn root runner, dispatch Spawn, pidfd reaping, report ingest
    lib.rs                       `SnapshotCurious`/`SnapshotCautious` wrappers around curious()/cautious()
                                 (phase 1 wraps; graduation replaces with `.with_snapshots()` on the builders)
  examples/
    expensive_setup.rs           demo target (10.2)
    snapshot_demo.rs             the "snapshot after setup, N continuations" demo + timing table
  tests/
    replay_equivalence.rs        continuation coverage == from-scratch coverage for 1k random cases
    fd_refusal.rs                holder refused when a socket/pipe fd is open; allowed with override
```

Changes needed inside the base crate to make the wrapper possible without
forking the crate (small, additive, keep `cargo test` green):

* `pub(crate)` hooks in `CaseRng`: `on_span_start(kind, cursor)` callback slot
  (a `Option<Box<dyn FnMut(SemanticKind, usize)>>`) invoked from
  `mark_semantic`/`RangeIter`/`variant`; accessor to install RNG state
  (`set_stream(seed, prefix, zero_tail, cursor)`) and to read
  `trace/draws/semantics/sequences` (a `snapshot_state()` returning a
  `Case`-like struct plus cursor). Feature-gated `snapshot` cfg.
* `State`: a way to record an externally produced
  `(Candidate, ExecutionFeedback, spans)` — factor the tail of
  `CaseRng::coverage()` into `State::record_execution(..)`.
* `CoverageCapture::peek_capture` provided method (§7).

### 10.2 Demo target: `examples/expensive_setup.rs`

A deterministic in-memory key/value store with a write-ahead log replay as
setup:

1. Setup (expensive, ~100 ms – 2 s configurable): build `n_records` records
   (`rng.range(0..n_records)` — a span, so it is shrinkable) into a `BTreeMap`
   plus a secondary index (`Vec<u64>` sorted), sized to hit 10 MB / 100 MB /
   1 GB RSS via a `--rss` argument; allocate the big vectors with
   `madvise(MADV_HUGEPAGE)` behind a flag to measure both.
2. `rng.checkpoint_hint()`.
3. Operations: `rng.range(0..64)` of `rng.variant(6)` ∈ {insert, delete,
   range-scan, compact, snapshot-to-index, rollback} with small payload spans.
4. Model check after each op against a reference `BTreeMap`; the injected bug
   is in `compact` after a `rollback` that crossed an index page boundary —
   requires a specific op *sequence* on top of a large state, so both the
   setup and the tail matter.
5. Harness: the README's curious→`fork_case`→cautious pattern, unchanged
   apart from `.with_snapshots(...)`.

Also keep `examples/buggy_stack.rs` as the negative control: with setup cost
≈ 0 the policy must decide *not* to snapshot and throughput must stay within
5 % of today.

### 10.3 Steps

1. `bench/`: move the five throwaway C programs in, add `run.sh`; re-measure
   on the target box and update §1 (½ day).
2. `proto.rs` + `runner.rs` minimal: root runner fork inside `next()`, report
   on finish, no holders. Verify `cargo test` of the base crate unchanged;
   measure per-execution overhead of the forkserver shape on `buggy_stack`
   (expect ≈ +0.35 ms/exec at 10 MB RSS; this is the number that says whether
   snapshots must be opt-in per loop — they must).
3. Holders: fork at hinted boundary only (`SnapshotPolicy::only_hinted()`),
   `Spawn`, continuation resume inside `next_byte`. Demo:
   `snapshot_demo --rss 10|100|1000 --continuations N` prints setup time,
   snapshot time, per-continuation time, and the same with snapshots disabled.
4. `replay_equivalence.rs`: 1 000 random candidates, run both ways, assert
   identical `features` sets; run with Sancov inline counters, trace-pc-guard,
   and `NoCoverage`.
5. Policy: span-boundary candidates, cost cliff, cost model, curious/cautious
   `expected_reuse`, budget/eviction. Measure on the demo: time-to-first-bug
   and cautious time-to-minimal with/without snapshots.
6. fd handling: fdinfo capture/`lseek` restore, refusal rules, tests.
7. Parallel continuations (`parallelism = 4/8`), compare against
   `ParallelCases` on `buggy_stack_bench`.
8. Write-up: update this memo with tables; decide graduation into `src/`
   behind `.with_snapshots()`.

Rough effort: steps 1–4 one session, 5–8 one to two sessions.

### 10.4 What will be measured (success criteria)

* Snapshot (holder creation) and continuation latency vs RSS at 10 MB, 100 MB,
  1 GB, 4 K pages and THP; expected to match §1.1 within noise.
* Demo: setup time `S`, `N` continuations from one holder vs `N` from-scratch
  runs; report speedup `N·S / (S + fork_cost + N·(tail + overhead))` and the
  break-even `N`.
* Curious on the demo target: executions/s, distinct features found in a fixed
  wall budget, with and without snapshots; count of holders created/evicted;
  fraction of candidates that found a holder and the mean `k / prefix_len`.
* Cautious on a found case: reductions/s and wall time to the minimal case,
  with and without snapshots; fraction of reductions served by a holder.
* Negative control: `buggy_stack` throughput with policy on (must not
  snapshot) within 5 % of baseline.
* Replay-equivalence violations: must be 0 on the demo; report the count on
  `buggy_stack` (it uses `Vec`/`VecDeque` only, expected 0).
* Memory: peak RSS of the whole tree at `max_holders = 32` on the 1 GB target.

## 11. Risks and unknowns

1. **Fork overhead dominates on cheap targets.** Measured: 0.34 ms round trip
   at 10 MB vs microsecond executions. Mitigation: opt-in, cost-model gating,
   §5.3 in-place reset later. Unknown: real-world RSS of typical dowsing
   harnesses under `cargo test` (probably 20–50 MB → ~0.5–1 ms/exec).
2. **Harness code runs in a child.** `println!` buffering, `Drop` not running
   after `_exit`, test frameworks' output capture, `#[test]` threads
   (libtest runs tests on threads → the runner has >1 thread → refusal
   rule fires). Mitigation: document; `--test-threads=1` or a
   `dowsing::main`-style wrapper; fall back to no-snapshot mode when
   `Threads: > 1`. Needs checking early (step 2).
3. **Determinism assumptions.** Pointer-hashing, `HashMap` with
   `RandomState`, `Instant`, `getrandom` before the checkpoint make
   continuation ≠ replay. Mitigation: replay-equivalence test and `discard()`;
   full fix is the sandbox spike.
4. **fd sharing** (§6). Continuations reading the same regular file race on
   offsets; sockets cannot be isolated. Mitigation: `lseek` restore, refusal
   rules; full fix is the sandbox spike or VM snapshots.
5. **Holder tree resource leaks** if P is `SIGKILL`ed: `PR_SET_PDEATHSIG` is
   per *thread* of the parent — if P's calling thread exits but the process
   lives, children get the signal spuriously; use `pidfd`-based liveness or
   `PR_SET_CHILD_SUBREAPER` + a tiny reaper. Needs a test.
6. **Coverage token/lock state inherited by continuations.** `CAPTURE_LOCK`
   is a process-global `AtomicBool`; in a continuation it is already "held"
   (inherited). Fine as long as continuations never call `start_capture`
   again; nested `cautious()` inside a runner (README pattern) does — it must
   run in the runner as a normal in-process loop, which today's code supports,
   but the inner loop must be told snapshots are off (recursion depth flag).
7. **`MAX_PREFIX_LEN = 4096`.** Spans and prefixes are truncated at 4 KiB of
   stream; snapshots beyond that only help candidates with the same seed and
   no mutation past the cap. Fine for phase 1; note for the expensive-setup
   demo that the setup should not consume thousands of bytes (draw sizes with
   a few `range`s, derive the bulk data deterministically from them).
8. **THP dependence.** The 10× fork speedup needs `madvise(MADV_HUGEPAGE)` on
   the big allocations or `enabled=always`; Rust's allocator won't do that by
   itself. A `dowsing::hugepage_vec` helper or documentation item.
9. **rr-style thread recreation (phase 2)** correctness for threads inside
   blocking syscalls and for `rseq`/robust futex lists — known hard; rr solves
   it with tight control of scheduling, which we will not have until the
   scheduler spike lands.
10. **Kernel behaviour drift.** `clear_refs` writable by owner, `UFFD_USER_MODE_ONLY`
    unprivileged, `pagemap` soft-dirty visible: all verified on 6.8 here; CI
    or developer boxes may differ (e.g. hardened kernels restrict `pagemap`).
    The design only *needs* `fork`, `socketpair`, `SCM_RIGHTS`, `pidfd_open`;
    everything else is optimisation.
11. **Measurement caveat.** All numbers are from an 8-vCPU AWS VM; bare-metal
    or a busy box will shift absolute values but not the ordering between
    mechanisms, which is what the recommendation rests on.

## 12. Prior art consulted and what was taken from each

* rr (`src/Session.cc`, `src/Task.cc`): checkpoint = injected `fork` of the
  leader (`os_fork_into`) + injected `clone` per extra thread
  (`os_clone_into`) + `copy_state`; shared mappings are copied out
  (`captured_memory`) because fork cannot snapshot them. → §1.2, §4.6, §9.
* AFL++ forkserver / deferred `__AFL_INIT()`; libAFL `InProcessForkExecutor`;
  AFL-Snapshot-LKM (kernel module: 1.2–3.6× over fork by resetting dirty
  pages in place — the same effect §5.3 seeks with soft-dirty from user
  space). → §3, §5.3.
* gVisor platforms doc: `systrap` (seccomp `SECCOMP_RET_TRAP` → `SIGSYS`)
  replaced `ptrace` as default because per-stop ptrace context switches are
  slow. → prefer in-process `fork` and seccomp-notif over ptrace supervision
  where possible (§4.6, §1.5).
* Nyx/kAFL: incremental VM snapshots by dirty-page logging are the ceiling;
  out of scope, protocol designed to allow swapping in (§4.4).
* Shuttle / Loom: deterministic scheduling by controlling every
  synchronisation point with a seedable/DFS scheduler; snapshots of a
  multithreaded process only make sense once the scheduler owns those points
  (§9).
* Antithesis: tree of timelines branching from snapshots at injected events;
  "each event potentially starts a new timeline" is our "each span boundary is
  a candidate checkpoint" (§8.1), and its guidance component is our energy
  based `expected_reuse` (§8.2).
* Hypothesis (`ConjectureData` choice sequence, shrinking by deleting/lowering
  choice blocks) and proptest (value-tree simplification): dowsing's
  span-based reducers are already this; the snapshot index keyed by byte
  prefix is the natural cache for a shrinker that edits later choices more
  often than earlier ones (§8.2 cautious).
* Man pages: fork(2) (what is and is not inherited — §6), userfaultfd(2)
  (`UFFD_USER_MODE_ONLY`, WP mode, WP_ASYNC), proc_pid_clear_refs(5) (value 4,
  pagemap bit 55), ptrace(2) (`PTRACE_SEIZE`/`INTERRUPT`, `PTRACE_EVENT_FORK`,
  auto-attach of forked children).
