use iterator_fuzz::{NoCoverage, cautious, curious};
use rand::Rng;
use std::{
    env,
    time::{Duration, Instant},
};

#[derive(Debug, Default)]
struct Bench {
    variants: usize,
    generated: usize,
    accepted: usize,
    discarded: usize,
    next: Duration,
    replay: Duration,
    coverage: Duration,
    discard: Duration,
}

impl Bench {
    fn print(&self) {
        let total = self.next + self.replay + self.coverage + self.discard;
        println!(
            "reducer benchmark over {} requested variants:",
            self.variants
        );
        println!("  generated: {}", self.generated);
        println!("  accepted:  {}", self.accepted);
        println!("  discarded: {}", self.discarded);
        print_duration("next/reducer", self.next, total);
        print_duration("rng replay", self.replay, total);
        print_duration("coverage", self.coverage, total);
        print_duration("discard", self.discard, total);
        let per_variant = if self.generated == 0 {
            0.0
        } else {
            total.as_secs_f64() * 1_000_000.0 / self.generated as f64
        };
        println!(
            "  total: {:.3}ms ({per_variant:.2}us/generated)",
            total.as_secs_f64() * 1_000.0
        );
    }
}

fn print_duration(label: &str, duration: Duration, total: Duration) {
    let percent = if total.is_zero() {
        0.0
    } else {
        duration.as_secs_f64() * 100.0 / total.as_secs_f64()
    };
    println!(
        "  {label}: {:.3}ms ({percent:.1}%)",
        duration.as_secs_f64() * 1_000.0
    );
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let variants = env_usize("REDUCER_BENCH_VARIANTS", 16_384);
    let words = env_usize("REDUCER_BENCH_WORD_DRAWS", 128);
    let bytes = env_usize("REDUCER_BENCH_BYTE_DRAWS", 128);
    let byte_len = env_usize("REDUCER_BENCH_BYTE_LEN", 8);
    let seed = env_u64("REDUCER_BENCH_SEED", 0);

    let mut source = curious().with_coverage(NoCoverage).with_seed(seed);
    let case = {
        let mut rng = source.next().expect("source rng");
        consume_case(&mut rng, words, bytes, byte_len);
        rng.fork_case()
    };

    let mut search = cautious().with_coverage(NoCoverage).with_case(case);
    {
        let mut seed_variant = search.next().expect("seed variant");
        consume_case(&mut seed_variant, words, bytes, byte_len);
        seed_variant.coverage().expect("seed coverage");
    }

    let mut bench = Bench {
        variants,
        ..Bench::default()
    };

    for index in 0..variants {
        let next_start = Instant::now();
        let Some(mut variant) = search.next() else {
            break;
        };
        bench.next += next_start.elapsed();
        bench.generated += 1;

        let replay_start = Instant::now();
        consume_case(&mut variant, words, bytes, byte_len);
        bench.replay += replay_start.elapsed();

        if index % 4 == 0 {
            let coverage_start = Instant::now();
            variant.coverage().expect("variant coverage");
            bench.coverage += coverage_start.elapsed();
            bench.accepted += 1;
        } else {
            let discard_start = Instant::now();
            variant.discard();
            bench.discard += discard_start.elapsed();
            bench.discarded += 1;
        }
    }

    bench.print();
}

fn consume_case(rng: &mut impl Rng, words: usize, bytes: usize, byte_len: usize) {
    for _ in 0..words {
        let _ = rng.random::<u32>();
    }
    let mut buffer = vec![0; byte_len];
    for _ in 0..bytes {
        rng.fill(&mut buffer[..]);
    }
}
