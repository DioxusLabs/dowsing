//! Find a real ordering bug in a stack that tracks a `reversed` flag.
//!
//! The "buggy" implementation tries to be clever: instead of physically reversing its storage on
//! `Reverse`, it flips a flag and adapts `push` to prepend when reversed. But `pop` was never
//! updated — it still pops from the physical end regardless of the flag. The fuzzer will find
//! that bug and minimize it to a tiny repro.
//!
//! Run with `cargo run --example buggy_stack`.

use iterator_fuzz::{CaseIteratorExt, Fuzzer, Step};
use rand::{
    Rng,
    distr::{Distribution, StandardUniform},
};

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

/// The model: a `Vec<i32>` that actually reverses on `Reverse`.
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

/// The buggy implementation: keeps a `reversed` flag but `pop` ignores it.
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
        // BUG: should be `if self.reversed { self.data.remove(0) ... }`.
        self.data.pop()
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
    match *step.op {
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
                    step.index
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

/// `Reverse` is the operation we suspect of being load-bearing in the bug, so make it cheap so
/// the reducer keeps it; make `Pop` slightly costlier so it prefers shorter pop-trails.
fn cost(op: &Op) -> u64 {
    match op {
        Op::Reverse => 1,
        Op::Push(_) => 1,
        Op::Pop => 2,
    }
}

fn main() {
    let bug = Fuzzer::sequences(StandardUniform)
        .base_seed(0)
        .seeds(256)
        .steps(64)
        .failures(Harness::default, apply)
        .minimize(cost)
        .next();

    match bug {
        None => println!("no bug found in 256 seeds × 64 ops"),
        Some(bug) => {
            println!("seed {} failed:", bug.seed);
            println!("  original {} ops -> minimized to {} ops", bug.ops.len(), bug.minimized_ops.len());
            println!("  minimized repro:");
            for (i, op) in bug.minimized_ops.iter().enumerate() {
                println!("    {i}: {op:?}");
            }
            println!("  minimized error: {}", bug.minimized_error);
        }
    }
}
