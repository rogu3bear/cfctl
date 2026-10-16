//! Ephemeral facts recorded by the owner of one admitted invocation.
//!
//! This is neither approval nor durable evidence. It survives executor clones
//! only so a failed response or local finalization cannot erase a dispatch.
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchKind {
    Read,
    Mutation,
}

#[derive(Clone, Debug, Default)]
pub struct BoundaryObservation {
    attempted: Arc<AtomicBool>,
    mutation_attempted: Arc<AtomicBool>,
}

impl BoundaryObservation {
    /// Call at the actual transport dispatch or successful process launch,
    /// never from a response flag, status code, error string or plan intent.
    pub fn record_dispatch(&self, kind: DispatchKind) {
        self.attempted.store(true, Ordering::Release);
        if kind == DispatchKind::Mutation {
            self.mutation_attempted.store(true, Ordering::Release);
        }
    }

    #[must_use]
    pub fn attempted(&self) -> bool {
        self.attempted.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn mutation_attempted(&self) -> bool {
        self.mutation_attempted.load(Ordering::Acquire)
    }
}
