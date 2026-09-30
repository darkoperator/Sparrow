//! Per-phase wall times of a detection run, for the performance report. Phases are recorded in
//! a thread-local by the code that runs (`Case::with_file_released`, the rule connection, the
//! runner) and drained into the [`DetectReport`](super::DetectReport); nothing reads them back
//! for a result, so they never change one.

use serde::Serialize;
use std::cell::RefCell;
use std::time::Instant;

#[derive(Debug, Clone, Serialize)]
pub struct Phase {
    pub name: String,
    pub ms: u64,
}

thread_local! {
    static PHASES: RefCell<Vec<Phase>> = const { RefCell::new(Vec::new()) };
}

/// Record that `name` took the time since `since` (repeated names add up).
pub(crate) fn record(name: &str, since: Instant) {
    let ms = since.elapsed().as_millis() as u64;
    PHASES.with(|p| {
        let mut p = p.borrow_mut();
        match p.iter_mut().find(|x| x.name == name) {
            Some(x) => x.ms += ms,
            None => p.push(Phase {
                name: name.to_string(),
                ms,
            }),
        }
    });
}

/// Take (and clear) the phases recorded on this thread.
pub(crate) fn take() -> Vec<Phase> {
    PHASES.with(|p| std::mem::take(&mut *p.borrow_mut()))
}
