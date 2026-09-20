//! The schedule loop: when no thread runs, offer the runnable threads, the models' events and
//! the pending timers as one `Schedule` decision (or take the only option), and decide what an
//! idle process means.

use super::Session;
use crate::{ptrace, sched::MAX_IDLE_FIRES, world::*};
use std::io;

impl Session {
    pub(super) fn schedule(&mut self) -> io::Result<()> {
        let sched = &self.world.sched;
        let runnable = sched.runnable();
        let mut candidates: Vec<Candidate> = Vec::new();
        if let Some(last) = sched.last_ran
            && runnable.contains(&last)
        {
            candidates.push(Candidate::Run(last));
        }
        candidates.extend(
            runnable
                .iter()
                .copied()
                .filter(|i| Some(*i) != sched.last_ran)
                .map(Candidate::Run),
        );
        let events = self.model_events();
        if candidates.is_empty() && events.is_empty() {
            return self.handle_idle();
        }
        candidates.extend(events);
        // Timers come after the world's events so the default choice drives the protocol
        // forward, and stop being offered once they have fired MAX_IDLE_FIRES times with
        // nothing else happening: a periodic timer must not let a run outlast its peers.
        if self.world.sched.idle_fires < MAX_IDLE_FIRES {
            candidates.extend(
                self.world
                    .sched
                    .timed_waiters()
                    .into_iter()
                    .map(Candidate::Fire),
            );
        }
        if candidates.len() >= 2 {
            self.world.pending = Some(Pending::Schedule { candidates });
            return Ok(());
        }
        self.apply_candidate(candidates[0], false)
    }

    pub(super) fn apply_candidate(
        &mut self,
        candidate: Candidate,
        contended: bool,
    ) -> io::Result<()> {
        match candidate {
            Candidate::Run(thread) => {
                let others = self.world.sched.runnable().iter().any(|i| *i != thread);
                if contended && others {
                    self.world.pending = Some(Pending::Budget { thread });
                    Ok(())
                } else {
                    self.resume(thread, 0)
                }
            }
            Candidate::Fire(thread) => self.fire_timeout(thread),
            Candidate::Ext(ev) => self.model_act(ev),
        }
    }

    fn fire_timeout(&mut self, thread: usize) -> io::Result<()> {
        let sched = &mut self.world.sched;
        let state = sched.threads[thread].state;
        let deadline = state.deadline().expect("fire on untimed thread");
        sched.clock_ns = sched.clock_ns.max(deadline);
        let ret = match state {
            ThreadState::FutexWait { .. } => -(libc::ETIMEDOUT as i64),
            _ => 0,
        };
        self.set_return(thread, ret)?;
        let sched = &mut self.world.sched;
        sched.threads[thread].state = ThreadState::Stopped;
        sched.threads[thread].blocked = None;
        sched.idle_fires += 1;
        self.record(thread, Point::Timeout);
        Ok(())
    }

    pub(super) fn resume(&mut self, index: usize, budget: u32) -> io::Result<()> {
        self.shm.set_budget(budget);
        let sched = &mut self.world.sched;
        let tid = sched.threads[index].tid;
        ptrace::cont(tid, 0)?;
        sched.threads[index].state = ThreadState::Running;
        sched.current = Some(index);
        sched.last_ran = Some(index);
        Ok(())
    }

    /// Nothing runnable and no event the world could inject: the earliest timeout fires, or
    /// the run is over and the oracle says how (see `Oracle::idle`).
    fn handle_idle(&mut self) -> io::Result<()> {
        if self.recheck_futex_words()? {
            return Ok(());
        }
        if self.world.sched.idle_fires < MAX_IDLE_FIRES
            && let Some(first) = self.world.sched.timed_waiters().first().copied()
        {
            return self.fire_timeout(first);
        }
        if self.world.sched.waiters().is_empty() {
            return Err(io::Error::other("no threads left but no outcome"));
        }
        let model_failure = self.model_idle();
        self.world.outcome = Some(self.world.oracle.idle(&self.world.sched, model_failure));
        Ok(())
    }
}
