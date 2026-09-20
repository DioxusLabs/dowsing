//! Explore a sandboxed target: tree search from snapshots, then replay + shrink any failure.
//!
//!   cargo run --release -p dowsing-sandbox --example explore -- targets/target/release/lost_update
//!
//! Flags: --runs N  --seed S  --verbose  --snapshot-every K  --keep-going  --replays N
//!        --fanout N  --pct-depth D  --ucb C
//!        --clients N  --request 'GET /x HTTP/1.1\r\n...'  (repeatable; `\r\n` escapes)
//!        --corpus DIR  (every file is one request)

use dowsing_sandbox::{Budget, Options, Search, Session, tree::Tuning, tree::format_decisions};
use std::time::Duration;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut program = None;
    let mut runs = 500;
    let mut seed = 1;
    let mut verbose = false;
    let mut snapshot_every = 8;
    let mut keep_going = false;
    let mut replays = 20;
    let mut wall = 120;
    let mut tuning = Tuning::default();
    let mut clients = 0;
    let mut requests: Vec<Vec<u8>> = Vec::new();
    let mut target_args = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--clients" => clients = args.next().unwrap().parse().unwrap(),
            "--request" => requests.push(unescape(&args.next().unwrap())),
            "--corpus" => {
                let dir = args.next().unwrap();
                let mut files: Vec<_> = std::fs::read_dir(&dir)
                    .expect("corpus dir")
                    .map(|e| e.unwrap().path())
                    .collect();
                files.sort();
                for f in files {
                    requests.push(std::fs::read(f).unwrap());
                }
            }
            "--runs" => runs = args.next().unwrap().parse().unwrap(),
            "--wall" => wall = args.next().unwrap().parse().unwrap(),
            "--seed" => seed = args.next().unwrap().parse().unwrap(),
            "--snapshot-every" => snapshot_every = args.next().unwrap().parse().unwrap(),
            "--replays" => replays = args.next().unwrap().parse().unwrap(),
            "--fanout" => tuning.budget_fanout = args.next().unwrap().parse().unwrap(),
            "--pct-depth" => tuning.pct_depth = args.next().unwrap().parse().unwrap(),
            "--ucb" => tuning.ucb_c = args.next().unwrap().parse().unwrap(),
            "--verbose" => verbose = true,
            "--keep-going" => keep_going = true,
            _ if program.is_none() => program = Some(a),
            _ => target_args.push(a),
        }
    }
    let program = program.expect("usage: explore <target> [--runs N] [--wall SECS] [--seed S]");
    let t = std::time::Instant::now();
    let session = Session::spawn(
        &program,
        &target_args,
        Options {
            verbose,
            max_clients: clients,
            requests,
            ..Options::default()
        },
    )
    .expect("spawn");
    let mut search = Search::new(session, seed).expect("root");
    println!(
        "root: exec + run to first decision in {:.2?} (cost of a fresh execution)",
        t.elapsed()
    );
    search.snapshot_every = snapshot_every;
    search.verbose = verbose;
    search.tuning = tuning;
    let budget = Budget {
        runs,
        wall: Duration::from_secs(wall),
        stop_on_failure: !keep_going,
    };
    search.run(&budget).expect("search");
    println!("{}", search.stats());
    println!(
        "tree: {} nodes, {} snapshots, {:.1} MB page store",
        search.nodes.len(),
        search.session.store.snapshots.len(),
        search.session.store.bytes as f64 / 1e6
    );
    if !search.session.uncontrolled.is_empty() {
        let mut u = search.session.uncontrolled.clone();
        u.sort();
        u.dedup();
        println!("uncontrolled: {u:?}");
    }
    let Some(failure) = search.stats.failures.first().cloned() else {
        println!("no failure found");
        return;
    };
    if keep_going {
        let mut distinct: Vec<(String, usize, usize)> = Vec::new();
        for f in &search.stats.failures {
            let key = format!(
                "{} {}",
                f.outcome,
                f.stderr.trim().lines().nth(1).unwrap_or("")
            );
            match distinct.iter_mut().find(|(k, _, _)| *k == key) {
                Some((_, _, count)) => *count += 1,
                None => distinct.push((key, f.run, 1)),
            }
        }
        println!("\ndistinct failures:");
        for (key, first, count) in distinct {
            println!("  first on run {first}, {count}x: {key}");
        }
    }
    println!("\nfailure on run {}: {}", failure.run, failure.outcome);
    println!(
        "decisions ({}): {}",
        failure.decisions.len(),
        format_decisions(&failure.decisions)
    );
    if !failure.stderr.trim().is_empty() {
        for line in failure.stderr.trim().lines().take(2) {
            println!("stderr: {line}");
        }
    }

    let choices: Vec<u32> = failure.decisions.iter().map(|d| d.choice).collect();
    let mut hashes = std::collections::HashSet::new();
    let mut outcomes = std::collections::HashSet::new();
    let t = std::time::Instant::now();
    for _ in 0..replays {
        let r = search.replay(&choices).expect("replay");
        hashes.insert(r.trace_hash);
        outcomes.insert(r.outcome);
    }
    println!(
        "replay x{replays}: {} distinct trace hash(es), outcomes {:?}, {:.1?} each",
        hashes.len(),
        outcomes,
        t.elapsed() / replays.max(1) as u32
    );

    let t = std::time::Instant::now();
    let (small, used) = search
        .shrink(&failure.decisions, &failure.outcome, 400)
        .expect("shrink");
    let non_default =
        |d: &[dowsing_sandbox::world::Decision]| d.iter().filter(|d| d.choice != 0).count();
    println!(
        "shrink: {} -> {} non-default choices ({} -> {} decisions total) in {} runs, {:.2?}",
        non_default(&failure.decisions),
        non_default(&small),
        failure.decisions.len(),
        small.len(),
        used,
        t.elapsed()
    );
    println!("minimal: {}", format_decisions(&small));
    println!("{}", search.stats());
}

fn unescape(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.extend(c.to_string().as_bytes());
            continue;
        }
        match chars.next() {
            Some('r') => out.push(b'\r'),
            Some('n') => out.push(b'\n'),
            Some(o) => out.extend(o.to_string().as_bytes()),
            None => out.push(b'\\'),
        }
    }
    out
}
