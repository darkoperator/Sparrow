//! `Output\LogFile.txt` (research event layouts §0.2): `yyyy-MM-dd HH:mm:ss: <message>` in the
//! host's local time, one `Out-File -Append` per entry (UTF-16LE with BOM on PowerShell 5.1,
//! UTF-8 on 7). A message holding `` `n `` keeps a bare LF inside its entry.

use super::Ctx;
use crate::Result;
use crate::ps::Encoding;
use crate::tree::{FileSpec, Tree};
use chrono::NaiveDateTime;

#[derive(Debug, Default)]
pub(crate) struct Log {
    entries: Vec<(NaiveDateTime, String)>,
}

impl Log {
    pub fn add(&mut self, t: NaiveDateTime, message: impl Into<String>) {
        self.entries.push((t, message.into()));
    }

    /// Writes the log: `LogFile.txt` at the collection root, or with `non_windows` a file named
    /// `Output\LogFile.txt` beside `Output/` (outside the collection, not in the manifest).
    pub fn write(self, c: &Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
        let mut text = String::new();
        for (t, m) in &self.entries {
            text.push_str(&format!("{}: {m}{}", t.format("%Y-%m-%d %H:%M:%S"), c.nl()));
        }
        let enc = Encoding::out_file_default(c.opts.ps);
        if c.opts.non_windows {
            tree.write_unlisted("Output\\LogFile.txt", &enc.encode(&text))
        } else {
            tree.write(
                &FileSpec::new("LogFile.txt", Some("inv.logfile"), enc),
                &text,
            )?;
            Ok(())
        }
    }
}
