//! Stateful search loop with a deliberately subtle stack bug.
//!
//! Run with LLVM SanitizerCoverage instrumentation:
//!
//! `cargo rustc --example buggy_stack -- -Cpasses=sancov-module \
//! -Cllvm-args=-sanitizer-coverage-level=3 \
//! -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
//! -Cllvm-args=-sanitizer-coverage-pc-table \
//! -Cllvm-args=-sanitizer-coverage-trace-compares`
//!
//! `./target/debug/examples/buggy_stack`

use dowsing::{cautious, curious};
use rand::Rng;
use std::collections::VecDeque;

const DISCOVERY_CASES: usize = 8_192;
const MINIMIZATION_CASES: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Push(i32),
    Pop,
    Flip,
    Spill,
    Flush,
    Save,
    Restore,
}

fn sample(rng: &mut impl Rng) -> Vec<Op> {
    let len = usize::from(rng.random::<u8>() % 80);

    (0..len)
        .map(|_| match rng.random::<u8>() % 7 {
            0 => Op::Push(i32::from(rng.random::<u8>() % 16)),
            1 => Op::Pop,
            2 => Op::Flip,
            3 => Op::Spill,
            4 => Op::Flush,
            5 => Op::Save,
            _ => Op::Restore,
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Model {
    stack: Vec<i32>,
    spill: Vec<i32>,
    saved: Option<(Vec<i32>, Vec<i32>)>,
}

impl Model {
    fn apply(&mut self, op: Op) -> Option<i32> {
        match op {
            Op::Push(value) => self.stack.push(value),
            Op::Pop => return self.stack.pop(),
            Op::Flip => self.stack.reverse(),
            Op::Spill => {
                if let Some(value) = self.stack.pop() {
                    self.spill.push(value);
                }
            }
            Op::Flush => self.stack.extend(self.spill.drain(..).rev()),
            Op::Save => self.saved = Some((self.stack.clone(), self.spill.clone())),
            Op::Restore => {
                if let Some((stack, spill)) = &self.saved {
                    self.stack.clone_from(stack);
                    self.spill.clone_from(spill);
                }
            }
        }
        None
    }
}

#[derive(Debug, Clone)]
struct Actual {
    deque: VecDeque<i32>,
    spill: Vec<i32>,
    reversed: bool,
    saved: Option<(VecDeque<i32>, Vec<i32>, bool)>,
}

impl Actual {
    fn logical_stack(&self) -> Vec<i32> {
        if self.reversed {
            self.deque.iter().rev().copied().collect()
        } else {
            self.deque.iter().copied().collect()
        }
    }

    fn apply(&mut self, op: Op) -> Option<i32> {
        match op {
            Op::Push(value) if self.reversed => self.deque.push_front(value),
            Op::Push(value) => self.deque.push_back(value),
            Op::Pop if self.reversed => return self.deque.pop_front(),
            Op::Pop => return self.deque.pop_back(),
            Op::Flip => self.reversed = !self.reversed,
            Op::Spill => {
                if let Some(value) = self.apply(Op::Pop) {
                    self.spill.push(value);
                }
            }
            Op::Flush => {
                while let Some(value) = self.spill.pop() {
                    self.apply(Op::Push(value));
                }
            }
            Op::Save => self.saved = Some((self.deque.clone(), self.spill.clone(), self.reversed)),
            Op::Restore => {
                if let Some((deque, spill, _reversed)) = &self.saved {
                    self.deque.clone_from(deque);
                    self.spill.clone_from(spill);
                    // BUG: restore forgets to restore orientation.
                }
            }
        }
        None
    }
}

fn check_stack(ops: &[Op]) -> Result<(), String> {
    let mut model = Model {
        stack: Vec::new(),
        spill: Vec::new(),
        saved: None,
    };
    let mut actual = Actual {
        deque: VecDeque::new(),
        spill: Vec::new(),
        reversed: false,
        saved: None,
    };

    for (index, op) in ops.iter().copied().enumerate() {
        let expected = model.apply(op);
        let actual_value = actual.apply(op);
        if actual_value != expected {
            return Err(format!(
                "op {index} returned {actual_value:?}, expected {expected:?}: {ops:?}"
            ));
        }
    }

    let actual_stack = actual.logical_stack();
    if actual_stack != model.stack {
        return Err(format!(
            "final stack {actual_stack:?}, expected {:?}: {ops:?}",
            model.stack
        ));
    }

    if actual.spill != model.spill {
        return Err(format!(
            "spill {:?}, expected {:?}: {ops:?}",
            actual.spill, model.spill
        ));
    }

    Ok(())
}

fn main() {
    // Maximize code coverage between when rng is created and dropped in the body of the loop, to increase the chance of hitting the bug.
    for mut rng in curious().take(DISCOVERY_CASES) {
        let ops = sample(&mut rng);
        if let Err(_err) = check_stack(&ops) {
            let case = rng.fork_case();
            let _coverage = rng.coverage().expect("finish discovery coverage");
            // Minimize the code executed by the discovery loop, to increase the chance of hitting the bug in the minimization loop.
            let mut cautious = cautious().with_case(case);
            let mut best = None;
            for mut variant in cautious.by_ref().take(MINIMIZATION_CASES) {
                let ops = sample(&mut variant);
                if let Err(error) = check_stack(&ops) {
                    let coverage = variant.coverage().expect("finish minimization coverage");
                    if best
                        .as_ref()
                        .is_none_or(|(best_coverage, _, _)| coverage < *best_coverage)
                    {
                        best = Some((coverage, ops, error));
                    }
                } else {
                    // exclude this from the minimization search space, since it doesn't trigger the bug.
                    variant.discard();
                }
            }

            if let Some((coverage, ops, failure)) = best {
                println!(
                    "found stack bug with {} features and {} bytes: {:?}\nerror: {}",
                    coverage.feature_count(),
                    coverage.bytes_consumed(),
                    ops,
                    failure
                );
                return;
            }
        }
    }
}
