//! Named phase durations of one command (`--timings`): a core function that takes an optional recorder times its
//! phases into it; with none it records nothing.

use serde::{Serialize, Serializer};
use std::time::{Duration, Instant};

/// The phases timed so far, in the order they ran.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Timings(pub Vec<(&'static str, Duration)>);

impl Timings {
    pub fn new() -> Timings {
        Timings::default()
    }

    /// Run `f`, recording how long it took as `name`.
    pub fn time<T>(&mut self, name: &'static str, f: impl FnOnce() -> T) -> T {
        let start = Instant::now();
        let out = f();
        self.0.push((name, start.elapsed()));
        out
    }

    /// Record `name` as taking `d` (a phase timed elsewhere).
    pub fn add(&mut self, name: &'static str, d: Duration) {
        self.0.push((name, d));
    }

    /// One line per phase, `name  1.234 s`, for stderr.
    pub fn lines(&self) -> Vec<String> {
        self.0
            .iter()
            .map(|(n, d)| format!("{n}  {:.3} s", d.as_secs_f64()))
            .collect()
    }
}

/// `--timings` with a recorder or without: `time` runs `f` either way.
pub fn time<T>(t: &mut Option<&mut Timings>, name: &'static str, f: impl FnOnce() -> T) -> T {
    match t {
        Some(t) => t.time(name, f),
        None => f(),
    }
}

/// As JSON: `[{"phase": name, "ms": 12.3}, ...]` in run order.
impl Serialize for Timings {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Phase {
            phase: &'static str,
            ms: f64,
        }
        s.collect_seq(self.0.iter().map(|(n, d)| Phase {
            phase: n,
            ms: (d.as_secs_f64() * 1_000_000.0).round() / 1000.0,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_phases_in_order() {
        let mut t = Timings::new();
        let v = t.time("one", || 1);
        t.time("two", || ());
        assert_eq!(v, 1);
        assert_eq!(
            t.0.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            ["one", "two"]
        );
        let j = serde_json::to_value(&t).unwrap();
        assert_eq!(j[0]["phase"], "one");
        assert!(j[1]["ms"].is_number());
        let mut none: Option<&mut Timings> = None;
        assert_eq!(time(&mut none, "x", || 2), 2);
    }
}
