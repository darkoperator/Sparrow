//! `Out-LogFile` (research hawk layouts §3): `Hawk.log` lines `[yyyy-MM-dd HH:mm:ssZ] -
//! [LEVEL] - message` in UTC (INFO padded with three spaces, ERROR with two, PROMPT followed by
//! two spaces, untagged `-NoDisplay` lines), and `_Investigate.txt`, which receives the
//! `-Notice` lines (also in Hawk.log) and the `-SilentNotice` `Additional Information: <path>`
//! lines (only there). Both files are written once at the end with `Out-File`'s default
//! encoding of the session that created them.

use crate::Result;
use crate::ps::Encoding;
use crate::rng::Rng;
use crate::tree::{FileSpec, Tree};
use chrono::{DateTime, Duration, Utc};
use std::collections::BTreeSet;

/// The two log files of one Hawk output folder, with the clock that stamps their lines.
#[derive(Debug, Clone)]
pub struct Log {
    clock: DateTime<Utc>,
    rng: Rng,
    lines: Vec<String>,
    investigate: Vec<String>,
}

impl Log {
    /// A log whose first line is stamped `start`; `rng` draws the seconds between lines.
    pub fn new(start: DateTime<Utc>, rng: Rng) -> Log {
        Log {
            clock: start,
            rng,
            lines: Vec::new(),
            investigate: Vec::new(),
        }
    }

    pub fn now(&self) -> DateTime<Utc> {
        self.clock
    }

    /// Moves the clock `lo..=hi` seconds forward.
    pub fn tick(&mut self, lo: i64, hi: i64) {
        let s = self.rng.range(lo, hi);
        self.clock += Duration::seconds(s);
    }

    /// Moves the clock to `t` when it is later.
    pub fn advance_to(&mut self, t: DateTime<Utc>) {
        if t > self.clock {
            self.clock = t;
        }
    }

    fn stamp(&self) -> String {
        self.clock.format("[%Y-%m-%d %H:%M:%SZ]").to_string()
    }

    fn push(&mut self, tag: &str, msg: &str) {
        let line = format!("{} - {tag}{msg}", self.stamp());
        self.lines.push(line);
    }

    /// `-Action`.
    pub fn action(&mut self, msg: impl AsRef<str>) {
        self.push("[ACTION] - ", msg.as_ref());
    }

    /// `-Information`.
    pub fn info(&mut self, msg: impl AsRef<str>) {
        self.push("[INFO]   - ", msg.as_ref());
    }

    /// `-isError`.
    pub fn error(&mut self, msg: impl AsRef<str>) {
        self.push("[ERROR]  - ", msg.as_ref());
    }

    /// `-isWarning`.
    pub fn warning(&mut self, msg: impl AsRef<str>) {
        self.push("[WARNING] - ", msg.as_ref());
    }

    /// `-isPrompt`.
    pub fn prompt(&mut self, msg: impl AsRef<str>) {
        self.push("[PROMPT] -  ", msg.as_ref());
    }

    /// No level switch (`-NoDisplay` lines): untagged.
    pub fn plain(&mut self, msg: impl AsRef<str>) {
        self.push("", msg.as_ref());
    }

    /// `-Notice`: the same line in Hawk.log and `_Investigate.txt`.
    pub fn notice(&mut self, msg: impl AsRef<str>) {
        let line = format!("{} - [INVESTIGATE] - {}", self.stamp(), msg.as_ref());
        self.lines.push(line.clone());
        self.investigate.push(line);
    }

    /// `-SilentNotice`: only `_Investigate.txt`.
    pub fn silent_notice(&mut self, path: impl AsRef<str>) {
        let line = format!(
            "{} - [INVESTIGATE] - Additional Information: {}",
            self.stamp(),
            path.as_ref()
        );
        self.investigate.push(line);
    }

    /// The Hawk.log lines written so far.
    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// The `_Investigate.txt` lines written so far.
    pub fn investigate_lines(&self) -> &[String] {
        &self.investigate
    }

    /// Writes `Hawk.log` and, when a notice was logged, `_Investigate.txt` into the root with
    /// `encoding` and `nl` line ends. `_Investigate.txt` loads one `collector_flags` row per
    /// distinct line.
    pub fn write(&self, tree: &mut Tree<'_>, encoding: Encoding, nl: &str) -> Result<()> {
        let join = |lines: &[String]| {
            lines
                .iter()
                .map(|l| format!("{}{nl}", l.replace('\n', nl)))
                .collect::<String>()
        };
        tree.write(
            &FileSpec::new("Hawk.log", Some("hawk.log"), encoding),
            &join(&self.lines),
        )?;
        if !self.investigate.is_empty() {
            let rel = "_Investigate.txt";
            tree.write(
                &FileSpec::new(rel, Some("hawk.investigate_txt"), encoding),
                &join(&self.investigate),
            )?;
            let distinct: BTreeSet<&String> = self.investigate.iter().collect();
            tree.rows_at_least(rel, "collector_flags", distinct.len() as u64);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::stream;

    #[test]
    fn levels_are_padded_as_out_logfile_pads_them() {
        let t: DateTime<Utc> = "2026-09-04T11:00:00Z".parse().unwrap();
        let mut log = Log::new(t, stream(1, "t"));
        log.info("a");
        log.error("b");
        log.prompt(" c");
        log.plain("d");
        log.notice("e");
        log.silent_notice("C:\\x\\Tenant\\f.csv");
        assert_eq!(
            log.lines(),
            [
                "[2026-09-04 11:00:00Z] - [INFO]   - a",
                "[2026-09-04 11:00:00Z] - [ERROR]  - b",
                "[2026-09-04 11:00:00Z] - [PROMPT] -   c",
                "[2026-09-04 11:00:00Z] - d",
                "[2026-09-04 11:00:00Z] - [INVESTIGATE] - e",
            ]
        );
        assert_eq!(
            log.investigate_lines()[1],
            "[2026-09-04 11:00:00Z] - [INVESTIGATE] - Additional Information: C:\\x\\Tenant\\f.csv"
        );
    }
}
