//! The `examples/buggy_stack.rs` state machine, upgraded to structured draws.
//!
//! Included via `#[path]` by both the child target and the supervisor demo so the harness code
//! is compiled (and, for the child, instrumented) inside the binary that runs it.

#![allow(dead_code)]

use coverage_bridge::Verdict;
use iterator_fuzz::{CaseRng, coverage::CoverageCapture};
use rand::Rng;
use std::collections::VecDeque;

pub const MAX_OPS: usize = 80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Push(i32),
    Pop,
    Flip,
    Spill,
    Flush,
    Save,
    Restore,
}

pub fn sample<Capture: CoverageCapture>(rng: &mut CaseRng<Capture>) -> Vec<Op> {
    rng.range(0..=MAX_OPS)
        .map(|mut item| match item.variant(7) {
            0 => Op::Push(i32::from(item.random::<u8>() % 16)),
            1 => Op::Pop,
            2 => Op::Flip,
            3 => Op::Spill,
            4 => Op::Flush,
            5 => Op::Save,
            _ => Op::Restore,
        })
        .collect()
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Model {
    stack: Vec<i32>,
    spill: Vec<i32>,
    saved: Option<(Vec<i32>, Vec<i32>)>,
}

impl Model {
    fn apply(&mut self, op: Op) -> Option<i32> {
        match op {
            Op::Push(value) => {
                self.stack.push(value);
                None
            }
            Op::Pop => self.stack.pop(),
            Op::Flip => {
                self.stack.reverse();
                None
            }
            Op::Spill => {
                if let Some(value) = self.stack.pop() {
                    self.spill.push(value);
                }
                None
            }
            Op::Flush => {
                while let Some(value) = self.spill.pop() {
                    self.stack.push(value);
                }
                None
            }
            Op::Save => {
                self.saved = Some((self.stack.clone(), self.spill.clone()));
                None
            }
            Op::Restore => {
                if let Some((stack, spill)) = &self.saved {
                    self.stack.clone_from(stack);
                    self.spill.clone_from(spill);
                }
                None
            }
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Actual {
    deque: VecDeque<i32>,
    spill: Vec<i32>,
    reversed: bool,
    saved: Option<(VecDeque<i32>, Vec<i32>, bool)>,
}

impl Actual {
    fn push(&mut self, value: i32) {
        if self.reversed {
            self.deque.push_front(value);
        } else {
            self.deque.push_back(value);
        }
    }

    fn pop(&mut self) -> Option<i32> {
        if self.reversed {
            self.deque.pop_front()
        } else {
            self.deque.pop_back()
        }
    }

    fn apply(&mut self, op: Op) -> Option<i32> {
        match op {
            Op::Push(value) => {
                self.push(value);
                None
            }
            Op::Pop => self.pop(),
            Op::Flip => {
                self.reversed = !self.reversed;
                None
            }
            Op::Spill => {
                if let Some(value) = self.pop() {
                    self.spill.push(value);
                }
                None
            }
            Op::Flush => {
                while let Some(value) = self.spill.pop() {
                    self.push(value);
                }
                None
            }
            Op::Save => {
                self.saved = Some((self.deque.clone(), self.spill.clone(), self.reversed));
                None
            }
            Op::Restore => {
                if let Some((deque, spill, _reversed)) = &self.saved {
                    self.deque.clone_from(deque);
                    self.spill.clone_from(spill);
                    // BUG: restore forgets to restore orientation.
                }
                None
            }
        }
    }

    fn stack(&self) -> Vec<i32> {
        let mut values: Vec<i32> = self.deque.iter().copied().collect();
        if self.reversed {
            values.reverse();
        }
        values
    }
}

pub fn check_stack(ops: &[Op]) -> Result<(), String> {
    let mut model = Model::default();
    let mut actual = Actual::default();

    for (index, op) in ops.iter().copied().enumerate() {
        let expected = model.apply(op);
        let got = actual.apply(op);
        if expected != got {
            return Err(format!(
                "op {index} {op:?}: got {got:?}, expected {expected:?}: {ops:?}"
            ));
        }
    }

    let actual_stack = actual.stack();
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

/// One harness invocation: sample an op list and check it. Cost is the op count so
/// `cautious()` prefers shorter reproductions.
pub fn run_case<Capture: CoverageCapture>(rng: &mut CaseRng<Capture>) -> (Verdict, Vec<Op>) {
    let ops = sample(rng);
    let verdict = match check_stack(&ops) {
        Ok(()) => Verdict::ok().with_cost(ops.len() as u64),
        Err(_) => Verdict::failed().with_cost(ops.len() as u64),
    };
    (verdict, ops)
}
