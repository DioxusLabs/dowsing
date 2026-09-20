//! Copy of the buggy stack model from `examples/buggy_stack.rs`, kept in sync by hand so the
//! bench harness measures exactly the target the demo uses.

use std::collections::VecDeque;

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

pub fn check_stack(ops: &[Op]) -> Result<(), String> {
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
