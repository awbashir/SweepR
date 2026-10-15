//! Scan-wide probe progress.
//!
//! The engine runs several probing subsystems at once (raw L2 jobs, the routed ICMP sweep,
//! the ICMP fallback). Each gets a [`ProgressScope`] with a fixed budget carved out of one
//! shared [`ProgressCounter`], so the combined `sent / total` the engine reports only ever
//! grows and never restarts when a subsystem starts or finishes.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

#[derive(Debug, Default)]
struct Counters {
    sent: AtomicU64,
    total: AtomicU64,
}

/// Shared, monotonic probe counters for one scan.
#[derive(Debug, Clone, Default)]
pub struct ProgressCounter {
    inner: Arc<Counters>,
}

impl ProgressCounter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve `budget` probes for one subsystem. The budget is added to the total now.
    pub fn scope(&self, budget: u64) -> ProgressScope {
        self.inner.total.fetch_add(budget, Ordering::Relaxed);
        ProgressScope {
            counter: self.clone(),
            budget,
            used: Arc::new(AtomicU64::new(0)),
        }
    }

    /// `(sent, total)`.
    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.inner.sent.load(Ordering::Relaxed),
            self.inner.total.load(Ordering::Relaxed),
        )
    }
}

/// A subsystem's share of a [`ProgressCounter`]. Cheap to clone; clones share the budget.
#[derive(Debug, Clone)]
pub struct ProgressScope {
    counter: ProgressCounter,
    budget: u64,
    used: Arc<AtomicU64>,
}

impl ProgressScope {
    /// A scope backed by its own private counter (for callers that do not aggregate).
    pub fn detached(budget: u64) -> Self {
        ProgressCounter::new().scope(budget)
    }

    /// Count `n` more probes as sent. Never exceeds the scope's budget.
    pub fn add(&self, n: u64) {
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            let next = cur.saturating_add(n).min(self.budget);
            if next == cur {
                return;
            }
            match self
                .used
                .compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => {
                    self.counter
                        .inner
                        .sent
                        .fetch_add(next - cur, Ordering::Relaxed);
                    return;
                }
                Err(actual) => cur = actual,
            }
        }
    }

    /// Mark the whole budget as done (e.g. a job that finished early or was skipped).
    pub fn finish(&self) {
        self.add(self.budget);
    }

    /// Probes counted so far in this scope.
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    pub fn budget(&self) -> u64 {
        self.budget
    }

    /// The counter this scope reports into.
    pub fn counter(&self) -> &ProgressCounter {
        &self.counter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_combine_monotonically() {
        let c = ProgressCounter::new();
        let a = c.scope(10);
        let b = c.scope(5);
        assert_eq!(c.snapshot(), (0, 15));
        a.add(4);
        b.add(7); // capped at its budget
        assert_eq!(c.snapshot(), (9, 15));
        a.finish();
        a.add(3); // already complete
        assert_eq!(c.snapshot(), (15, 15));
        assert_eq!((a.used(), b.used()), (10, 5));
        let late = c.scope(2);
        assert_eq!(c.snapshot(), (15, 17));
        late.clone().add(1);
        assert_eq!(late.used(), 1);
    }
}
