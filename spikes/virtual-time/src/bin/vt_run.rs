//! Run any program under the virtual-time sandbox once (natural time, no fuzzing) and print
//! the supervisor's report.  `vt_run [--events] [--no-hide-vdso] [--replay N] -- <prog> [args]`.

use std::time::Duration;

use iterator_fuzz::{NoCoverage, curious};
use virtual_time::Sandbox;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut events = false;
    let mut hide_vdso = true;
    let mut replays = 0_usize;
    let mut natural = true;
    let mut quiet = false;
    let mut wall_limit = 10_u64;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--events" => events = true,
            "--no-hide-vdso" => hide_vdso = false,
            "--quiet" => quiet = true,
            "--fuzz" => natural = false,
            "--replay" => {
                i += 1;
                replays = args[i].parse().expect("--replay N");
            }
            "--wall-limit" => {
                i += 1;
                wall_limit = args[i].parse().expect("--wall-limit SECS");
            }
            "--" => {
                i += 1;
                break;
            }
            other => panic!("unknown flag {other}"),
        }
        i += 1;
    }
    let prog = &args[i..];
    assert!(!prog.is_empty(), "usage: vt_run [flags] -- <prog> [args]");

    let mut sandbox = Sandbox::new(&prog[0])
        .keep_events(events)
        .hide_vdso(hide_vdso)
        .quiet(quiet)
        .wall_limit(Duration::from_secs(wall_limit));
    for a in &prog[1..] {
        sandbox = sandbox.arg(a);
    }
    // Natural mode: zero jumps drawn (max_jumps = 0) so time only advances to the next deadline.
    if natural {
        sandbox = sandbox.max_jumps(0);
    }

    let mut search = curious().with_coverage(NoCoverage);
    let mut rng = search.by_ref().take(1).next().expect("one case");
    let report = sandbox.run(&mut rng);
    let case = rng.fork_case();
    rng.discard();
    for line in &report.events {
        eprintln!("  {line}");
    }
    eprintln!(
        "outcome {:?}  virtual {:.6}s  wall {:.3}ms  hash {:#x}",
        report.outcome,
        report.virtual_elapsed.as_secs_f64(),
        report.wall.as_secs_f64() * 1e3,
        report.event_hash
    );
    eprintln!("stats {:?}", report.stats);
    eprintln!("decisions {:?}", report.decisions);

    let mut identical = 0;
    for _ in 0..replays {
        let mut rng = case.clone().replay();
        let again = sandbox.clone().quiet(true).run(&mut rng);
        rng.discard();
        if again.event_hash == report.event_hash && again.outcome == report.outcome {
            identical += 1;
        } else {
            eprintln!(
                "replay diverged: outcome {:?} hash {:#x}",
                again.outcome, again.event_hash
            );
        }
    }
    if replays > 0 {
        eprintln!("replays identical: {identical}/{replays}");
    }
    std::process::exit(if report.outcome.is_failure() { 1 } else { 0 });
}
