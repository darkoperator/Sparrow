//! `Out-LogFile` in its two dialects.
//!
//! Hawk 4.0 (research hawk layouts §3): `Hawk.log` lines `[yyyy-MM-dd HH:mm:ssZ] - [LEVEL] -
//! message` in UTC (INFO padded with three spaces, ERROR with two, PROMPT followed by two
//! spaces, untagged `-NoDisplay` lines), and `_Investigate.txt`, which receives the `-Notice`
//! lines (also in Hawk.log) and the `-SilentNotice` `Additional Information: <path>` lines (only
//! there).
//!
//! Hawk 3.1 (research §7.1, capture survey §1): every line stamped `[<Get-Date -Format G>]`,
//! the host culture's long date and time in the host's local time (`[M/d/yyyy h:mm:ss tt]` on
//! en-US, `[dd/MM/yyyy HH:mm:ss]` on en-GB); `[ACTION]`, `[ERROR]` and `[WARNING]` tags, every
//! other line untagged; `-Notice` lines are `## <Tag> ##` lines (in both files), the tag naming
//! the section that logged them (`Log::section`); `-SilentNotice` writes an indented
//! `Additional Information: <path>` line to `_Investigate.txt` only (research §7.1: "indented
//! `<Label> <Label>: <Windows path>` lines"). The culture timestamps are date evidence of both
//! files.
//!
//! Both files are written once at the end with `Out-File`'s default encoding of the session
//! that created them.

use crate::Result;
use crate::ps::{DateEvidence, DtKind, Encoding, Host, PsDate, note_evidence};
use crate::rng::Rng;
use crate::tree::{FileSpec, Tree};
use chrono::{DateTime, Duration, Utc};
use std::collections::BTreeSet;

/// Which Hawk wrote the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// Hawk 4.0: UTC ISO stamps, padded level tags.
    V4,
    /// Hawk 3.1: stamps in the culture and local time of this host.
    V3(Host),
}

/// The level of one `Hawk.log` line (the PSFramework export of Hawk 3 lists them too).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Action,
    Info,
    Error,
    Warning,
    Prompt,
    Plain,
    Notice,
}

/// One `Hawk.log` line before rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub at: DateTime<Utc>,
    pub level: Level,
    pub message: String,
}

/// The two log files of one Hawk output folder, with the clock that stamps their lines.
#[derive(Debug, Clone)]
pub struct Log {
    clock: DateTime<Utc>,
    rng: Rng,
    dialect: Dialect,
    lines: Vec<String>,
    entries: Vec<Entry>,
    investigate: Vec<String>,
    log_dates: DateEvidence,
    investigate_dates: DateEvidence,
    /// The Hawk 3 `## <Tag> ##` of notices logged now.
    section: String,
}

impl Log {
    /// A Hawk 4 log whose first line is stamped `start`; `rng` draws the seconds between lines.
    pub fn new(start: DateTime<Utc>, rng: Rng) -> Log {
        Log::with_dialect(start, rng, Dialect::V4)
    }

    /// A log of `dialect`.
    pub fn with_dialect(start: DateTime<Utc>, rng: Rng, dialect: Dialect) -> Log {
        Log {
            clock: start,
            rng,
            dialect,
            lines: Vec::new(),
            entries: Vec::new(),
            investigate: Vec::new(),
            log_dates: DateEvidence::default(),
            investigate_dates: DateEvidence::default(),
            section: "Hawk".into(),
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

    /// The stamp of a line written now; a Hawk 3 stamp is also noted in `ev`.
    fn stamp(&self, ev: &mut DateEvidence) -> String {
        match self.dialect {
            Dialect::V4 => self.clock.format("[%Y-%m-%d %H:%M:%SZ]").to_string(),
            Dialect::V3(host) => {
                note_evidence(&host, ev, &PsDate::dotnet(self.clock, DtKind::Local));
                format!("[{}]", host.culture_date(self.clock, DtKind::Local))
            }
        }
    }

    /// Adds the culture date `d` a Hawk 3 message carries to `Hawk.log`'s date evidence.
    pub fn note_date(&mut self, d: &PsDate) {
        if let Dialect::V3(host) = self.dialect {
            note_evidence(&host, &mut self.log_dates, d);
        }
    }

    /// Hawk 3: the section tag of the notices logged from now on.
    pub fn section(&mut self, tag: impl Into<String>) {
        self.section = tag.into();
    }

    /// The tag (with its separator) of `level` in this dialect.
    fn tag(&self, level: Level) -> String {
        if let (Dialect::V3(_), Level::Notice) = (self.dialect, level) {
            return format!("## {} ## - ", self.section);
        }
        match (self.dialect, level) {
            (Dialect::V4, Level::Action) => "[ACTION] - ",
            (Dialect::V4, Level::Info) => "[INFO]   - ",
            (Dialect::V4, Level::Error) => "[ERROR]  - ",
            (Dialect::V4, Level::Warning) => "[WARNING] - ",
            (Dialect::V4, Level::Prompt) => "[PROMPT] -  ",
            (Dialect::V4, Level::Notice) => "[INVESTIGATE] - ",
            (Dialect::V3(_), Level::Action) => "[ACTION] - ",
            (Dialect::V3(_), Level::Error) => "[ERROR] - ",
            (Dialect::V3(_), Level::Warning) => "[WARNING] - ",
            (_, _) => "",
        }
        .to_string()
    }

    fn push(&mut self, level: Level, msg: &str) -> String {
        let mut ev = DateEvidence::default();
        let line = format!("{} - {}{msg}", self.stamp(&mut ev), self.tag(level));
        self.log_dates.merge(&ev);
        self.lines.push(line.clone());
        self.entries.push(Entry {
            at: self.clock,
            level,
            message: msg.to_string(),
        });
        line
    }

    /// `-Action`.
    pub fn action(&mut self, msg: impl AsRef<str>) {
        self.push(Level::Action, msg.as_ref());
    }

    /// `-Information` (Hawk 3 has no such switch: an untagged line).
    pub fn info(&mut self, msg: impl AsRef<str>) {
        self.push(Level::Info, msg.as_ref());
    }

    /// `-isError`.
    pub fn error(&mut self, msg: impl AsRef<str>) {
        self.push(Level::Error, msg.as_ref());
    }

    /// `-isWarning`.
    pub fn warning(&mut self, msg: impl AsRef<str>) {
        self.push(Level::Warning, msg.as_ref());
    }

    /// `-isPrompt` (Hawk 3: an untagged line).
    pub fn prompt(&mut self, msg: impl AsRef<str>) {
        self.push(Level::Prompt, msg.as_ref());
    }

    /// No level switch (`-NoDisplay` lines): untagged.
    pub fn plain(&mut self, msg: impl AsRef<str>) {
        self.push(Level::Plain, msg.as_ref());
    }

    /// `-Notice`: the same line in Hawk.log and `_Investigate.txt`.
    pub fn notice(&mut self, msg: impl AsRef<str>) {
        let line = self.push(Level::Notice, msg.as_ref());
        if let Dialect::V3(host) = self.dialect {
            note_evidence(
                &host,
                &mut self.investigate_dates,
                &PsDate::dotnet(self.clock, DtKind::Local),
            );
        }
        self.investigate.push(line);
    }

    /// `-SilentNotice`: only `_Investigate.txt`.
    pub fn silent_notice(&mut self, path: impl AsRef<str>) {
        let line = match self.dialect {
            Dialect::V4 => format!(
                "{} - [INVESTIGATE] - Additional Information: {}",
                self.stamp(&mut DateEvidence::default()),
                path.as_ref()
            ),
            // source-derived (no 3.1 source): research §7.1 gives "indented `<Label> <Label>:
            // <Windows path>`"; the tab and the label text `Additional Information` (Hawk 4's) are
            // chosen.
            Dialect::V3(_) => format!("\tAdditional Information: {}", path.as_ref()),
        };
        self.investigate.push(line);
    }

    /// The Hawk.log lines written so far.
    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// The Hawk.log lines before rendering.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The `_Investigate.txt` lines written so far.
    pub fn investigate_lines(&self) -> &[String] {
        &self.investigate
    }

    /// The `collector_flags` rows `_Investigate.txt` loads: one per distinct record key, which
    /// the COMMENT (migration 8) defines as the hash of "<flag_type>\n<time text or
    /// empty>\n<message>" per entry: "a line [<time text>] - [TAG] - <message> or [<time
    /// text>] - ## <Tag> ## - <message> ... starts an entry with that time text and message
    /// (both trimmed); a line whose trimmed text starts with "Additional Information:" (Hawk 3
    /// writes it indented) is an entry of its own with that trimmed text as message and the time
    /// text of the entry above it". A Hawk 4 line is one entry; every Hawk 3 line this log
    /// writes is a stamped notice or an indented `Additional Information:` line.
    fn investigate_flags(&self) -> u64 {
        match self.dialect {
            Dialect::V4 => self.investigate.iter().collect::<BTreeSet<_>>().len() as u64,
            Dialect::V3(_) => {
                let mut stamp: Option<&str> = None;
                let mut seen: BTreeSet<(Option<&str>, &str)> = BTreeSet::new();
                for line in &self.investigate {
                    match line.strip_prefix('[').and_then(|l| l.split_once("] - ")) {
                        Some((ts, rest)) => {
                            stamp = Some(ts);
                            let msg = rest.split_once("## - ").map_or(rest, |(_, m)| m);
                            seen.insert((stamp, msg.trim()));
                        }
                        None => {
                            seen.insert((stamp, line.trim()));
                        }
                    }
                }
                seen.len() as u64
            }
        }
    }

    /// Writes `Hawk.log` and, when a notice was logged, `_Investigate.txt` into the root with
    /// `encoding` and `nl` line ends. `_Investigate.txt` loads one `collector_flags` row per
    /// distinct entry.
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
        if self.log_dates.culture_dates > 0 {
            tree.date_evidence("Hawk.log", self.log_dates);
        }
        if !self.investigate.is_empty() {
            let rel = "_Investigate.txt";
            tree.write(
                &FileSpec::new(rel, Some("hawk.investigate_txt"), encoding),
                &join(&self.investigate),
            )?;
            tree.rows_counted(rel, "collector_flags", self.investigate_flags());
            if self.investigate_dates.culture_dates > 0 {
                tree.date_evidence(rel, self.investigate_dates);
            }
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

    #[test]
    fn hawk3_lines_carry_local_culture_stamps_and_section_notices() {
        use crate::options::{Culture, PsEdition};
        let t: DateTime<Utc> = "2026-09-04T13:05:09Z".parse().unwrap();
        let host = Host::new(PsEdition::Ps51, Culture::EnUs, 120);
        let mut log = Log::with_dialect(t, stream(1, "t"), Dialect::V3(host));
        log.plain("*** Version 3.1.0 ***");
        log.info("a");
        log.action("b");
        log.section("Tenant");
        log.notice("c");
        log.silent_notice("C:\\x\\Tenant\\f.csv");
        log.silent_notice("C:\\x\\Tenant\\f.csv");
        assert_eq!(
            log.lines(),
            [
                "[9/4/2026 3:05:09 PM] - *** Version 3.1.0 ***",
                "[9/4/2026 3:05:09 PM] - a",
                "[9/4/2026 3:05:09 PM] - [ACTION] - b",
                "[9/4/2026 3:05:09 PM] - ## Tenant ## - c",
            ]
        );
        assert_eq!(
            log.investigate_lines()[1],
            "\tAdditional Information: C:\\x\\Tenant\\f.csv"
        );
        // The stamped notice and one indented line (the repeat has the same stamp).
        assert_eq!(log.investigate_flags(), 2);
        assert_eq!(log.log_dates.culture_dates, 4);
        assert_eq!(log.log_dates.decisive, 0);
    }
}
