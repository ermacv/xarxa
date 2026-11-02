//! Waker registration, for the `async` feature.
//!
//! Every socket keeps one waker per operation kind (receive, send, accept). The
//! stack wakes them whenever something happens that may change what the
//! corresponding operations return: a packet arriving, a TCP state transition,
//! room freeing up in a ring buffer. A future built on top can then poll the
//! socket, register, and go to sleep.

#![cfg_attr(not(any(feature = "tcp", feature = "udp", feature = "_raw")), allow(unused))]

use core::task::Waker;

/// Utility struct to register and wake a waker.
#[derive(Debug, Default)]
pub(crate) struct WakerRegistration {
    waker: Option<Waker>,
}

impl WakerRegistration {
    pub const fn new() -> Self {
        Self { waker: None }
    }

    /// Register a waker. Overwrites the previous waker, if any.
    pub fn register(&mut self, w: &Waker) {
        match self.waker {
            // Optimization: If both the old and new Wakers wake the same task, we can simply
            // keep the old waker, skipping the clone. (In most executor implementations,
            // cloning a waker is somewhat expensive, comparable to cloning an Arc).
            Some(ref w2) if (w2.will_wake(w)) => {}
            // In all other cases
            // - we have no waker registered
            // - we have a waker registered but it's for a different task.
            // then clone the new waker and store it
            _ => self.waker = Some(w.clone()),
        }
    }

    /// Wake the registered waker, if any.
    pub fn wake(&mut self) {
        if let Some(w) = self.waker.take() {
            w.wake()
        }
    }
}
