//! Basic interception checks run on a sandboxed test thread.

use std::io::Read;
use std::sync::Arc;

use fs_env_intercept::{Content, Sandbox, Spec};
use iterator_fuzz::{NoCoverage, curious};

fn spec(with_env: bool) -> Arc<Spec> {
    // Tests run on parallel threads sharing one process environment, so only one test applies
    // environment variables.
    let spec = Spec::new()
        .file("/etc/app/app.conf", Content::Fixed(b"mode=strict\n".to_vec()))
        .file("/var/lib/app/data.bin", Content::Random { max_len: 8 })
        .dir("/var/lib/app", 2)
        .symlink("/etc/app/link.conf", vec!["/etc/app/app.conf".into(), "missing".into()]);
    Arc::new(if with_env {
        spec.env("APP_MODE", vec![Some("lenient"), Some("strict"), None])
    } else {
        spec
    })
}

#[test]
fn getpid_is_answered_by_the_sandbox() {
    let mut sandbox = Sandbox::install().expect("install sandbox");
    let real = std::process::id();
    let spec = spec(false);
    let mut seen = std::collections::BTreeSet::new();
    for rng in curious().with_coverage(NoCoverage).take(40) {
        let (rng, report, pid) = sandbox.run_case(rng, &spec, std::process::id);
        assert!(report.trapped >= 1, "getpid was trapped: {report:?}");
        seen.insert(pid);
        rng.coverage().unwrap();
    }
    assert!(seen.contains(&real), "realistic pid variant appears: {seen:?}");
    assert!(seen.len() > 1, "interesting pid variants appear: {seen:?}");
    assert_eq!(std::process::id(), real, "outside a case getpid is native");
}

#[test]
fn threads_spawned_by_the_target_are_filtered_and_attributed() {
    let mut sandbox = Sandbox::install().expect("install sandbox");
    let spec = spec(false);
    let fuzz_tid = sandbox.fuzz_tid();
    let rng = curious().with_coverage(NoCoverage).next().unwrap();
    let (rng, report, (child_tid, conf)) = sandbox.run_case(rng, &spec, || {
        std::fs::read_to_string("/etc/app/app.conf").expect("virtual config on fuzz thread");
        std::thread::spawn(|| {
            // SAFETY: plain syscall.
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
            let conf = std::fs::read_to_string("/etc/app/app.conf").expect("virtual config on child");
            (tid, conf)
        })
        .join()
        .unwrap()
    });
    rng.discard();
    assert_eq!(conf, "mode=strict\n");
    assert_ne!(child_tid, fuzz_tid);
    assert!(report.per_tid.contains_key(&fuzz_tid), "{:?}", report.per_tid);
    // The child's own tid is a fuzzer variant, but the kernel reports the real tid in the
    // notification; the child made at least the openat of the config.
    let child_calls: u64 = report
        .per_tid
        .iter()
        .filter(|(tid, _)| **tid != fuzz_tid)
        .map(|(_, n)| *n)
        .sum();
    assert!(child_calls >= 1, "{:?}", report.per_tid);
    if let Some(cpu) = sandbox.pinned_cpu() {
        // SAFETY: plain syscall.
        assert_eq!(unsafe { libc::sched_getcpu() } as usize, cpu, "fuzz thread stays pinned");
    }
}

#[test]
fn virtual_file_and_directory_are_served() {
    let mut sandbox = Sandbox::install().expect("install sandbox");
    let spec = spec(true);
    for rng in curious().with_coverage(NoCoverage).take(10) {
        let (rng, report, ()) = sandbox.run_case(rng, &spec, || {
            let conf = std::fs::read_to_string("/etc/app/app.conf").expect("virtual config");
            assert_eq!(conf, "mode=strict\n");
            let meta = std::fs::metadata("/etc/app/app.conf").expect("virtual stat");
            assert_eq!(meta.len(), 12);
            let data = std::fs::read("/var/lib/app/data.bin").expect("virtual data");
            assert!(data.len() <= 8);
            let mut names: Vec<String> = std::fs::read_dir("/var/lib/app")
                .expect("virtual dir")
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            assert!(names.contains(&"data.bin".to_string()), "{names:?}");
            match std::fs::read_link("/etc/app/link.conf") {
                Ok(target) => assert!(
                    target == std::path::Path::new("/etc/app/app.conf")
                        || target == std::path::Path::new("missing")
                ),
                Err(err) => panic!("readlink: {err}"),
            }
            assert!(std::fs::metadata("/etc/app/nope").is_err());
            assert!(std::fs::metadata("/etc").is_ok(), "real paths keep working");
            let mode = std::env::var("APP_MODE");
            assert!(matches!(mode.as_deref(), Ok("lenient") | Ok("strict") | Err(_)));
            let environ = std::fs::read("/proc/self/environ").expect("virtual environ");
            let has = environ.windows(9).any(|w| w == b"APP_MODE=");
            assert_eq!(has, mode.is_ok(), "environ reflects applied env");
        });
        assert!(report.virtual_opens >= 3, "{report:?}");
        assert!(report.unsupported.is_empty(), "{report:?}");
        rng.coverage_with_cost(report.cost()).unwrap();
    }
}

#[test]
fn entropy_is_supplied_and_replays() {
    let mut sandbox = Sandbox::install().expect("install sandbox");
    let spec = spec(false);
    let read_entropy = || {
        let mut file = std::fs::File::open("/dev/urandom").expect("open urandom");
        let mut buf = [0u8; 8];
        let n = file.read(&mut buf).map_err(|e| e.raw_os_error());
        let mut gr = [0u8; 16];
        // SAFETY: valid buffer.
        let m = unsafe { libc::getrandom(gr.as_mut_ptr().cast(), gr.len(), 0) };
        (n, buf, m, gr)
    };
    let mut first = None;
    for rng in curious().with_coverage(NoCoverage).take(20) {
        let (rng, report, out) = sandbox.run_case(rng, &spec, read_entropy);
        assert!(report.entropy_bytes > 0 || out.0.is_err() || out.2 < 0, "{report:?} {out:?}");
        let case = rng.fork_case();
        rng.coverage().unwrap();
        first.get_or_insert((case, out));
    }
    let (case, expected) = first.unwrap();
    for _ in 0..3 {
        let (rng, _report, out) = sandbox.run_case(case.clone().replay(), &spec, read_entropy);
        assert_eq!(out, expected, "replay is deterministic");
        rng.coverage().unwrap();
    }
}
