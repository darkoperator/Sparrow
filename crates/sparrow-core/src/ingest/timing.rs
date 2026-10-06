//! Opt-in wall-clock profile of an ingest (`SPARROW_INGEST_PROFILE=1`): named stage spans summed over the run
//! and one line per file. Off by default: a span is then one relaxed atomic load and no clock read. The report is
//! printed to stderr by the CLI when the variable is set; nothing in the case changes.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

/// 0 unknown, 1 off, 2 on.
static STATE: AtomicU8 = AtomicU8::new(0);
static SPANS: Mutex<BTreeMap<String, (u64, Duration)>> = Mutex::new(BTreeMap::new());
static FILES: Mutex<Vec<FileTiming>> = Mutex::new(Vec::new());

/// The environment variable that turns the profile on (any non-empty value but `0`).
pub const ENV: &str = "SPARROW_INGEST_PROFILE";

/// Whether profiling is on (read from [`ENV`] once).
pub fn enabled() -> bool {
    match STATE.load(Ordering::Relaxed) {
        2 => true,
        1 => false,
        _ => {
            let on = std::env::var(ENV).is_ok_and(|v| !v.is_empty() && v != "0");
            STATE.store(if on { 2 } else { 1 }, Ordering::Relaxed);
            on
        }
    }
}

/// Force profiling on or off (tests).
pub fn set_enabled(on: bool) {
    STATE.store(if on { 2 } else { 1 }, Ordering::Relaxed);
}

/// A running span: adds its elapsed time to `name` when dropped.
pub struct Span {
    name: Option<String>,
    start: Option<Instant>,
}

/// Time the rest of the scope under `name` (no-op when profiling is off).
pub fn span(name: &str) -> Span {
    if enabled() {
        Span {
            name: Some(name.to_string()),
            start: Some(Instant::now()),
        }
    } else {
        Span {
            name: None,
            start: None,
        }
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        if let (Some(name), Some(start)) = (self.name.take(), self.start) {
            add(&name, start.elapsed());
        }
    }
}

/// Add `d` to `name` (one call).
pub fn add(name: &str, d: Duration) {
    if !enabled() {
        return;
    }
    let mut m = SPANS.lock().unwrap_or_else(|e| e.into_inner());
    let e = m.entry(name.to_string()).or_default();
    e.0 += 1;
    e.1 += d;
}

/// One file's outcome and time.
#[derive(Debug, Clone)]
pub struct FileTiming {
    pub rel_path: String,
    pub artifact: Option<String>,
    pub status: String,
    pub bytes: u64,
    pub records: u64,
    pub elapsed: Duration,
}

pub fn file(t: FileTiming) {
    if enabled() {
        FILES.lock().unwrap_or_else(|e| e.into_inner()).push(t);
    }
}

/// The spans, sorted by name: (name, calls, total).
pub fn spans() -> Vec<(String, u64, Duration)> {
    SPANS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .map(|(k, (n, d))| (k.clone(), *n, *d))
        .collect()
}

pub fn files() -> Vec<FileTiming> {
    FILES.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Forget everything recorded so far.
pub fn reset() {
    SPANS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    FILES.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

/// The report: spans (name, calls, seconds), then files slowest first.
pub fn report() -> String {
    let mut out = String::from("ingest profile: spans (name, calls, seconds)\n");
    for (name, n, d) in spans() {
        out.push_str(&format!("  {name:<44} {n:>8} {:>10.3}\n", d.as_secs_f64()));
    }
    let mut fs = files();
    fs.sort_by_key(|a| std::cmp::Reverse(a.elapsed));
    out.push_str("ingest profile: files (seconds, status, bytes, records, artifact, path)\n");
    for f in fs {
        out.push_str(&format!(
            "  {:>9.3} {:<18} {:>12} {:>9} {:<36} {}\n",
            f.elapsed.as_secs_f64(),
            f.status,
            f.bytes,
            f.records,
            f.artifact.as_deref().unwrap_or("-"),
            f.rel_path
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_and_files_are_recorded_only_when_enabled() {
        set_enabled(false);
        reset();
        {
            let _s = span("off");
        }
        file(FileTiming {
            rel_path: "a".into(),
            artifact: None,
            status: "parsed".into(),
            bytes: 1,
            records: 1,
            elapsed: Duration::from_millis(1),
        });
        assert!(spans().is_empty() && files().is_empty());
        set_enabled(true);
        {
            let _s = span("on");
        }
        {
            let _s = span("on");
        }
        add("added", Duration::from_millis(5));
        let s = spans();
        assert_eq!(s.iter().find(|x| x.0 == "on").unwrap().1, 2);
        assert_eq!(
            s.iter().find(|x| x.0 == "added").unwrap().2,
            Duration::from_millis(5)
        );
        let r = report();
        assert!(r.contains("on") && r.contains("added"), "{r}");
        reset();
        set_enabled(false);
    }
}
