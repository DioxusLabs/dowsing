struct Harness {
    vdom: VirtualDom,
    incremental: TrackingTree,
}

impl Harness {
    fn fresh() -> Self {
        with_model(|m| *m = Model::new());
        let mut vdom = VirtualDom::new(App);
        let mut incremental = TrackingTree::new();
        vdom.rebuild(&mut incremental);
        Self { vdom, incremental }
    }
}

fn fresh_render() -> Vec<Canonical> {
    let mut vdom = VirtualDom::new(App);
    let mut tree = TrackingTree::new();
    vdom.rebuild(&mut tree);
    tree.canonical()
}

fn apply_step(state: &mut Harness, step: Step<'_, Op>) -> Result<(), String> {
    let op = *step.op;
    apply_to_model(op);
    state.vdom.mark_dirty(ScopeId::APP);

    let render_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.vdom.render_immediate(&mut state.incremental);
        if !state.incremental.stack.is_empty() {
            panic!(
                "render_immediate left mutation stack non-empty (len={})",
                state.incremental.stack.len()
            );
        }
        state.incremental.canonical()
    }));

    let incremental = match render_result {
        Ok(t) => t,
        Err(payload) => {
            return Err(format!(
                "step {} ({op:?}): panic in incremental render: {}",
                step.index,
                panic_message(&payload),
            ));
        }
    };

    // A re-render with no model change must emit zero mutations.
    state.vdom.mark_dirty(ScopeId::APP);
    let mut idempotent = Mutations::default();
    let idempotent_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.vdom.render_immediate(&mut idempotent);
    }));
    if let Err(payload) = idempotent_result {
        return Err(format!(
            "step {} ({op:?}): panic in no-change re-render: {}",
            step.index,
            panic_message(&payload),
        ));
    }
    if !idempotent.edits.is_empty() {
        return Err(format!(
            "step {} ({op:?}): re-render with no state change emitted {} mutation(s):\n  {:#?}",
            step.index,
            idempotent.edits.len(),
            idempotent.edits,
        ));
    }

    let fresh_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(fresh_render));
    let fresh = match fresh_result {
        Ok(t) => t,
        Err(payload) => {
            return Err(format!(
                "step {} ({op:?}): panic in FRESH rebuild: {}",
                step.index,
                panic_message(&payload),
            ));
        }
    };

    if incremental != fresh {
        return Err(format!(
            "step {} ({op:?}): incremental tree diverged from a fresh rebuild\n\
             incremental: {incremental:#?}\n\
             fresh:       {fresh:#?}",
            step.index
        ));
    }
    Ok(())
}

fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

fn cost(op: &Op) -> u64 {
    op.slots.iter().filter(|s| s.is_some()).count() as u64
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn coverage_sources() -> Vec<PathBuf> {
    std::env::var_os("FUZZ_COVERAGE_SOURCES")
        .map(|paths| std::env::split_paths(&paths).collect())
        .unwrap_or_else(|| vec![PathBuf::from("../dioxus/packages/core/src")])
}

fn coverage_collector() -> LlvmCoverage {
    let object = std::env::var_os("FUZZ_COVERAGE_OBJECT")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_exe().expect("failed to locate current executable"));
    let workdir = std::env::var_os("FUZZ_COVERAGE_WORKDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/iterator-fuzz-cov/dioxus-vdom-example"));
    let mut coverage = LlvmCoverage::new(object, coverage_sources(), workdir)
        .expect("failed to initialize LLVM coverage");
    if let Some(path) = std::env::var_os("LLVM_PROFDATA") {
        coverage = coverage.llvm_profdata(path);
    }
    if let Some(path) = std::env::var_os("LLVM_COV") {
        coverage = coverage.llvm_cov(path);
    }
    coverage
}

fn run_coverage_guided() {
    let seeds = env_u64("FUZZ_SEEDS", 128);
    let steps = env_usize("FUZZ_STEPS", 128);
    let max_cases = env_usize("FUZZ_COVERAGE_CASES", 64);
    let mut coverage = coverage_collector();
    let mut explorer = Fuzzer::sequences(StandardUniform)
        .base_seed(0)
        .seeds(seeds)
        .steps(steps)
        .coverage_guided(move |ops: &[Op]| {
            coverage
                .evaluate(|| replay_ops(ops, Harness::fresh, apply_step))
                .expect("failed to collect LLVM coverage")
        })
        .cost(cost);

    println!("coverage-guided fuzzing {seeds} seeds x {steps} ops, accepting up to {max_cases}");
    let mut accepted = 0usize;
    for case in (&mut explorer).take(max_cases) {
        accepted += 1;
        println!(
            "accepted #{accepted}: seed {:?}, len {}, +{} coverage ids",
            case.seed,
            case.len,
            case.unique_coverage.len()
        );
        if let Err(error) = &case.outcome {
            println!("failure after {} ops: {error}", case.ops.len());
            break;
        }
    }
    let stats = explorer.stats();
    println!(
        "coverage summary: generated {}, executed {}, accepted {}, failures {}, coverage ids {}",
        stats.generated, stats.executed, stats.accepted, stats.failures, stats.coverage_ids
    );
}

fn main() {
    if std::env::var_os("FUZZ_COVERAGE").is_some() {
        run_coverage_guided();
        return;
    }

    let seeds = env_u64("FUZZ_SEEDS", 32_768);
    let steps = env_usize("FUZZ_STEPS", 512);

    let workers = rayon::current_num_threads();
    println!(
        "fuzzing {seeds} seeds × {steps} ops across {workers} rayon workers (keyed-list focus)"
    );

    // VirtualDom is `!Send`, but each parallel case constructs its own Harness
    // inside the worker via `Harness::fresh` and never sends it elsewhere.
    let bug = Fuzzer::sequences(StandardUniform)
        .base_seed(0)
        .seeds(seeds)
        .steps(steps)
        .par()
        .minimized_failures(Harness::fresh, apply_step, cost)
        .find_any(|_| true);

    match bug {
        None => {
            println!(
                "no divergence: {seeds} seeds × {steps} ops (parallel) found no incremental/fresh mismatch"
            );
        }
        Some(bug) => {
            println!(
                "seed {} diverged: original {} ops -> minimized to {} ops",
                bug.seed,
                bug.ops.len(),
                bug.minimized_ops.len()
            );
            for (i, op) in bug.minimized_ops.iter().enumerate() {
                let prims: Vec<_> = op.slots.iter().flatten().collect();
                println!("  {i}: {prims:?}");
            }
            println!("minimized error: {}", bug.minimized_error);
        }
    }
}
