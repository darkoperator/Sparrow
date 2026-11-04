//! In-file progress: the [`IngestProgress::FileStep`] events of the file being handled, and the import-wide byte
//! count of the [`IngestProgress::File`] events.

use crate::ingest::{FILE_STEP_INTERVAL, IngestOptions, IngestProgress};
use std::cell::{Cell, RefCell};
use std::time::Instant;

/// Step 0 of every file: the admission read (hash, head, encoding).
pub const CHECKING_FILE: &str = "Checking file";

/// What the last event of a file reported.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Shown {
    step: usize,
    done: u64,
    records: u64,
    errors: u64,
}

/// The progress of one file: its steps (`"Checking file"` and its parser's), the current step and pass, and the
/// counts so far. Every method is a no-op when the ingest has no progress callback. Single-threaded: the parse
/// context and the record passes share it by reference.
pub(crate) struct FileProgress<'a> {
    opts: &'a IngestOptions,
    on: bool,
    steps: RefCell<Vec<&'static str>>,
    step: Cell<Option<usize>>,
    done: Cell<u64>,
    total: u64,
    records: Cell<u64>,
    errors: Cell<u64>,
    last_at: Cell<Option<Instant>>,
    shown: Cell<Option<Shown>>,
}

impl<'a> FileProgress<'a> {
    /// A file of `total` bytes, whose parser (as far as is known yet) has `parser_steps`.
    pub(crate) fn new(opts: &'a IngestOptions, parser_steps: &[&'static str], total: u64) -> Self {
        let p = FileProgress {
            opts,
            on: opts.progress.is_some(),
            steps: RefCell::new(Vec::new()),
            step: Cell::new(None),
            done: Cell::new(0),
            total,
            records: Cell::new(0),
            errors: Cell::new(0),
            last_at: Cell::new(None),
            shown: Cell::new(None),
        };
        p.set_parser_steps(parser_steps);
        p
    }

    /// The parser's steps, once the file is classified from its content (they follow `"Checking file"`).
    pub(crate) fn set_parser_steps(&self, parser_steps: &[&'static str]) {
        if !self.on {
            return;
        }
        let mut s = self.steps.borrow_mut();
        s.clear();
        s.push(CHECKING_FILE);
        s.extend_from_slice(parser_steps);
    }

    /// Start step `step` (an index into the full list, `"Checking file"` being 0). The step left is closed at 100 %
    /// first when its last event was below it (it read nothing, or only in a quiet pass). Starting the current step
    /// again does nothing.
    pub(crate) fn begin_step(&self, step: usize) {
        if !self.on || self.step.get() == Some(step) {
            return;
        }
        if self.step.get().is_some() {
            self.close();
        }
        self.step.set(Some(step));
        self.done.set(0);
        self.emit();
    }

    /// A pass over the file opens in step `step`: its bytes count from 0.
    pub(crate) fn begin_pass(&self, step: usize) {
        if !self.on {
            return;
        }
        self.begin_step(step);
        self.done.set(0);
    }

    /// `n` more bytes were read by the current pass: reported when [`FILE_STEP_INTERVAL`] has passed since the
    /// last event.
    pub(crate) fn read(&self, n: u64) {
        if !self.on {
            return;
        }
        self.done
            .set(self.done.get().saturating_add(n).min(self.total));
        let now = self.opts.now();
        if self
            .last_at
            .get()
            .is_none_or(|t| now.saturating_duration_since(t) >= FILE_STEP_INTERVAL)
        {
            self.emit_at(now);
        }
    }

    /// The current pass ended (it read the file to its end, or the parser stopped it early): the step is at 100 %.
    pub(crate) fn close(&self) {
        if !self.on || self.step.get().is_none() {
            return;
        }
        self.done.set(self.total);
        if self.shown.get() != Some(self.current()) {
            self.emit();
        }
    }

    /// The records loaded or staged so far and the records rejected so far; neither ever goes back.
    pub(crate) fn set_counts(&self, records: u64, errors: u64) {
        if !self.on {
            return;
        }
        self.records.set(self.records.get().max(records));
        self.errors.set(self.errors.get().max(errors));
    }

    /// `n` more records were staged for loading.
    pub(crate) fn add_staged(&self, n: u64) {
        if !self.on {
            return;
        }
        self.records.set(self.records.get() + n);
    }

    fn current(&self) -> Shown {
        Shown {
            step: self.step.get().unwrap_or(0),
            done: self.done.get(),
            records: self.records.get(),
            errors: self.errors.get(),
        }
    }

    fn emit(&self) {
        self.emit_at(self.opts.now());
    }

    fn emit_at(&self, now: Instant) {
        let Some(f) = &self.opts.progress else {
            return;
        };
        let shown = self.current();
        self.last_at.set(Some(now));
        self.shown.set(Some(shown));
        f(&IngestProgress::FileStep {
            steps: self.steps.borrow().clone(),
            step: shown.step,
            bytes_done: shown.done,
            bytes_total: self.total,
            records: shown.records,
            errors: shown.errors,
        });
    }
}

/// The import-wide byte count of the [`IngestProgress::File`] events: the bytes of the files to load, and the part
/// of them the files handled so far cover.
#[derive(Debug, Default)]
pub(crate) struct ImportBytes {
    pub(crate) done: u64,
    pub(crate) total: u64,
}
