//! Registry of long-running utility jobs (latency monitors, traceroutes, iPerf3 runs).
//!
//! Each job gets a numeric id (starting at 1) and a [`CancellationToken`]. Unlike the scan
//! manager (one scan at a time, a new one supersedes the old), utility jobs run side by side
//! up to a per-kind cap, are stopped individually by id, and are all cancelled when the app
//! exits.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, PoisonError,
    },
};

use tokio_util::sync::CancellationToken;

/// Running jobs of one kind.
#[derive(Debug)]
pub struct JobRegistry {
    kind: &'static str,
    max: usize,
    jobs: Mutex<HashMap<u64, CancellationToken>>,
    next_id: AtomicU64,
}

impl JobRegistry {
    /// A registry allowing at most `max` concurrent jobs, named `kind` in error messages.
    pub fn new(kind: &'static str, max: usize) -> Self {
        Self {
            kind,
            max: max.max(1),
            jobs: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
        }
    }

    /// Register a new job. Fails when `max` jobs are already running.
    pub fn begin(&self) -> Result<(u64, CancellationToken), String> {
        let mut jobs = self.jobs.lock().unwrap_or_else(PoisonError::into_inner);
        if jobs.len() >= self.max {
            return Err(format!(
                "{} {}s are already running; stop one first",
                self.max, self.kind
            ));
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let token = CancellationToken::new();
        jobs.insert(id, token.clone());
        Ok((id, token))
    }

    /// Cancel job `id`. Returns `true` when it was running.
    pub fn stop(&self, id: u64) -> bool {
        let jobs = self.jobs.lock().unwrap_or_else(PoisonError::into_inner);
        match jobs.get(&id) {
            Some(token) => {
                token.cancel();
                true
            }
            None => false,
        }
    }

    /// Forget job `id` (it finished). Its token is cancelled so helpers it spawned stop too.
    pub fn end(&self, id: u64) {
        let mut jobs = self.jobs.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(token) = jobs.remove(&id) {
            token.cancel();
        }
    }

    /// Cancel every running job (app exit).
    pub fn stop_all(&self) {
        let jobs = self.jobs.lock().unwrap_or_else(PoisonError::into_inner);
        for token in jobs.values() {
            token.cancel();
        }
    }

    /// Number of registered (running) jobs.
    pub fn len(&self) -> usize {
        self.jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `true` while job `id` is registered.
    pub fn is_running(&self, id: u64) -> bool {
        self.jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(&id)
    }
}

/// Runs a closure when dropped: ends a job even when its task panics or its future is
/// dropped half-way, so a registry slot can never leak.
pub struct OnDrop<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> OnDrop<F> {
    pub fn new(f: F) -> Self {
        OnDrop(Some(f))
    }
}

impl<F: FnOnce()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn slot_is_released_when_the_job_panics() {
        let r = std::sync::Arc::new(JobRegistry::new("trace", 1));
        let (id, _) = r.begin().unwrap();
        let reg = r.clone();
        let task = tokio::spawn(async move {
            let _end = OnDrop::new(move || reg.end(id));
            panic!("job crashed");
        });
        assert!(task.await.is_err());
        assert!(!r.is_running(id));
        assert!(r.begin().is_ok(), "the slot was released");
    }

    #[test]
    fn jobs_are_capped_stopped_and_ended() {
        let r = JobRegistry::new("trace", 2);
        let (a, ta) = r.begin().unwrap();
        let (b, tb) = r.begin().unwrap();
        assert!(a >= 1 && b > a);
        let err = r.begin().unwrap_err();
        assert!(err.contains("2 traces"), "{err}");
        assert!(r.stop(a) && ta.is_cancelled() && !tb.is_cancelled());
        assert!(
            r.is_running(a),
            "stopped jobs stay registered until they end"
        );
        r.end(a);
        assert!(!r.is_running(a) && !r.stop(a));
        let (_c, tc) = r.begin().unwrap();
        r.stop_all();
        assert!(tb.is_cancelled() && tc.is_cancelled());
        assert_eq!(r.len(), 2);
        r.end(b);
        assert_eq!(r.len(), 1);
        assert!(!r.is_empty());
    }
}
