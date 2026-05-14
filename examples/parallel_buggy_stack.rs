//! Same buggy stack as `buggy_stack.rs`, but fans 10k seeds across rayon worker threads and
//! returns the first minimized failure any thread finds.
//!
//! Run with `cargo run --example parallel_buggy_stack --features rayon --release`.

use iterator_fuzz::{Fuzzer, Step, parallel::ParCaseIteratorExt};
use rand::{
    Rng,
    distr::{Distribution, StandardUniform},
};
use rayon::iter::ParallelIterator;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Push(i32),
    Pop,
    Reverse,
}

impl Distribution<Op> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Op {
        match rng.random_range(0..3) {
            0 => Op::Push(rng.random_range(0..10)),
            1 => Op::Pop,
            _ => Op::Reverse,
        }
    }
}

#[derive(Debug, Default)]
struct ModelStack(Vec<i32>);
impl ModelStack {
    fn push(&mut self, v: i32) {
        self.0.push(v);
    }
    fn pop(&mut self) -> Option<i32> {
        self.0.pop()
    }
    fn reverse(&mut self) {
        self.0.reverse();
    }
}

#[derive(Debug, Default)]
struct LazyReverseStack {
    data: Vec<i32>,
    reversed: bool,
}
impl LazyReverseStack {
    fn push(&mut self, v: i32) {
        if self.reversed {
            self.data.insert(0, v);
        } else {
            self.data.push(v);
        }
    }
    fn pop(&mut self) -> Option<i32> {
        self.data.pop() // same bug as the serial example
    }
    fn reverse(&mut self) {
        self.reversed = !self.reversed;
    }
}

#[derive(Debug, Default)]
struct Harness {
    model: ModelStack,
    buggy: LazyReverseStack,
}

fn apply(h: &mut Harness, step: Step<'_, Op>) -> Result<(), String> {
    match *step.op() {
        Op::Push(v) => {
            h.model.push(v);
            h.buggy.push(v);
        }
        Op::Pop => {
            let expected = h.model.pop();
            let actual = h.buggy.pop();
            if expected != actual {
                return Err(format!(
                    "step {}: pop returned {actual:?}, expected {expected:?}",
                    step.index()
                ));
            }
        }
        Op::Reverse => {
            h.model.reverse();
            h.buggy.reverse();
        }
    }
    Ok(())
}

fn cost(op: &Op) -> u64 {
    match op {
        Op::Reverse | Op::Push(_) => 1,
        Op::Pop => 2,
    }
}

fn main() {
    // Note: par_failures / par_minimized_failures need `Fn + Send + Sync` closures, not `FnMut`.
    // `Harness::default` and `apply` are `fn` items, which satisfy this for free.
    let bug = Fuzzer::sequences(StandardUniform)
        .base_seed(0)
        .seeds(10_000)
        .steps(128)
        .par()
        .minimized_failures(Harness::default, apply, cost)
        .find_any(|_| true);

    match bug {
        None => println!("no bug found in 10_000 seeds × 128 ops"),
        Some(bug) => {
            println!("(parallel) seed {} failed:", bug.seed());
            println!(
                "  original {} ops -> minimized to {} ops",
                bug.ops().len(),
                bug.minimized_ops().len(),
            );
            println!("  minimized repro:");
            for (i, op) in bug.minimized_ops().iter().enumerate() {
                println!("    {i}: {op:?}");
            }
            println!("  minimized error: {}", bug.minimized_error());
        }
    }
}
