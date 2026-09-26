//! `Out-MultipleFileType` (Hawk `internal/functions/Out-MultipleFileType.ps1`; research hawk
//! layouts §2): collects its pipeline input and writes it as CSV (`Export-Csv -Encoding UTF8`,
//! header = the first object's properties), TXT (`Format-List * | Out-File`, default
//! encoding) and JSON (`ConvertTo-Json -Depth 100 | Out-File -Encoding UTF8`: one object gives
//! a bare object, several an array), in that order, into `<root>\Tenant` or `<root>\<User>`
//! as `<Prefix>[_<part of User before @>].<ext>`. `-Append` adds CSV rows under the existing
//! header and another complete JSON document; no input writes no file (`No Data Found`).
//! `-Notice` logs each written file to `_Investigate.txt`.
//!
//! The Tenant folder is `Join-Path <root> "\Tenant"`: with `non_windows` (PowerShell 7 on
//! macOS/Linux) that is a literal folder named `\Tenant` beside the `Tenant` folder the
//! collectors create themselves (research §1.1).

use super::log::Log;
use crate::Result;
use crate::ps::{
    DateEvidence, Encoding, Host, Row, convert_to_json, export_csv, export_csv_append, format_list,
};
use crate::tree::{FileSpec, Tree};
use crate::writers::parsed_by_sparrow;
use std::collections::{BTreeMap, BTreeSet};

/// Which files one call writes (`-csv`, `-json`, `-txt`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Formats {
    pub csv: bool,
    pub json: bool,
    pub txt: bool,
}

impl Formats {
    pub const CSV_JSON: Formats = Formats {
        csv: true,
        json: true,
        txt: false,
    };
    pub const CSV: Formats = Formats {
        csv: true,
        json: false,
        txt: false,
    };
    pub const JSON: Formats = Formats {
        csv: false,
        json: true,
        txt: false,
    };
    pub const TXT: Formats = Formats {
        csv: false,
        json: false,
        txt: true,
    };
}

/// One file a call wrote: its tree path and each object's 1-based line span in the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    pub rel: String,
    pub spans: Vec<(u32, u32)>,
}

/// The files one call wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Written {
    pub csv: Option<Part>,
    pub txt: Option<Part>,
    pub json: Option<Part>,
}

impl Written {
    pub fn parts(&self) -> impl Iterator<Item = &Part> {
        self.csv
            .iter()
            .chain(self.txt.iter())
            .chain(self.json.iter())
    }
}

/// What a Hawk file is to Sparrow, declared by the writer at each call site from the Hawk
/// research (layouts §1-§5): the artifact id the file is (Sparrow's name for it, as
/// `writers::SPARROW_PARSED` lists them), whether it is derived from another output of the
/// same run (`Simple_*` / `*_Simple_*` twins, `Converted_Authentication_Logs`, the appended
/// tenant roll-ups `All_SweepRules` and `User_ForwardingReport`, `Unique_Users_Attempted`),
/// and whether Sparrow has no parser for it. `manifest` / `check` then compare the declared
/// artifact with the one Sparrow assigns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Art {
    pub id: &'static str,
    pub derived: bool,
    pub not_supported: bool,
}

impl Art {
    /// A collector output Sparrow parses.
    pub const fn raw(id: &'static str) -> Art {
        Art {
            id,
            derived: false,
            not_supported: false,
        }
    }

    /// An output derived from another file of the run.
    pub const fn derived(id: &'static str) -> Art {
        Art {
            id,
            derived: true,
            not_supported: false,
        }
    }

    /// An output Sparrow classifies but has no parser for.
    pub const fn not_supported(id: &'static str) -> Art {
        Art {
            id,
            derived: false,
            not_supported: true,
        }
    }

    /// The same artifact, without a parser.
    pub const fn without_parser(self) -> Art {
        Art {
            not_supported: true,
            ..self
        }
    }
}

/// The `FileSpec` of Hawk file `rel` written with `encoding`: artifact `art`, subject the
/// folder a per-user / per-IP / per-message file sits in (`subject`). Panics when the
/// declaration and `SPARROW_PARSED` disagree about whether Sparrow parses the artifact, so a
/// parser added later makes the writer's declaration fail loudly instead of silently.
pub fn spec(rel: &str, encoding: Encoding, art: Art, subject: Option<&str>) -> FileSpec {
    assert_eq!(
        parsed_by_sparrow(art.id),
        !art.not_supported,
        "{rel}: {} is declared {}parsed",
        art.id,
        if art.not_supported { "not " } else { "" }
    );
    let mut s = FileSpec::new(rel, Some(art.id), encoding);
    s.derived = art.derived;
    s.subject = subject.map(str::to_string);
    if art.not_supported {
        s.expect_status = Some("not_supported");
    }
    s
}

/// The Out-MultipleFileType emulation of one Hawk output folder, with its log.
#[derive(Debug, Clone)]
pub struct Omft {
    /// The session writing (edition, culture, line ends): tenant and user investigations may
    /// run in different sessions.
    pub host: Host,
    pub log: Log,
    /// `$Hawk.FilePath` as the collecting host prints it.
    pub file_path: String,
    /// PowerShell 7 on macOS/Linux: `/` separators and the literal `\Tenant` folder.
    pub non_windows: bool,
    csv_headers: BTreeMap<String, Vec<String>>,
    json_docs: BTreeMap<String, u32>,
    dirs: BTreeSet<String>,
}

impl Omft {
    pub fn new(host: Host, log: Log, file_path: String, non_windows: bool) -> Omft {
        Omft {
            host,
            log,
            file_path,
            non_windows,
            csv_headers: BTreeMap::new(),
            json_docs: BTreeMap::new(),
            dirs: BTreeSet::new(),
        }
    }

    /// The folder (tree path) Out-MultipleFileType writes tenant files to.
    pub fn tenant_dir(&self) -> &'static str {
        if self.non_windows {
            "\\Tenant"
        } else {
            "Tenant"
        }
    }

    /// `Join-Path $Hawk.FilePath <dir> <file>` as the host prints it.
    pub fn shown(&self, dir: &str, file: &str) -> String {
        if self.non_windows {
            format!("{}/{dir}/{file}", self.file_path)
        } else {
            let dir = dir.trim_start_matches('\\');
            format!("{}\\{dir}\\{file}", self.file_path)
        }
    }

    /// Records that a collector created folder `dir` itself (`New-Item`, no log line).
    pub fn created(&mut self, dir: &str) {
        self.dirs.insert(dir.to_string());
    }

    /// The tree path of a file Out-MultipleFileType would write for `prefix`, `user` and
    /// extension `ext`.
    pub fn rel(&self, prefix: &str, user: Option<&str>, ext: &str) -> String {
        match user {
            Some(u) => {
                let short = u.split('@').next().unwrap_or(u);
                format!("{u}/{prefix}_{short}.{ext}")
            }
            None => format!("{}/{prefix}.{ext}", self.tenant_dir()),
        }
    }

    /// Writes `rows` like `rows | Out-MultipleFileType -FilePrefix <prefix> [-User <user>]
    /// <formats> [-Append] [-Notice]`. `user` is the `-User` string (a UPN, an IP folder, a
    /// message file name, and the files' subject); `art` what the files are to Sparrow. No
    /// rows: logs `No Data Found` and writes nothing.
    #[allow(clippy::too_many_arguments)]
    pub fn write(
        &mut self,
        tree: &mut Tree<'_>,
        prefix: &str,
        user: Option<&str>,
        art: Art,
        rows: &[Row],
        formats: Formats,
        append: bool,
        notice: bool,
    ) -> Result<Written> {
        let dir = match user {
            Some(u) => u.to_string(),
            None => self.tenant_dir().to_string(),
        };
        if !self.dirs.contains(&dir) {
            let (what, shown) = match user {
                Some(_) => ("user", self.shown_dir(&dir)),
                None => ("Tenant", self.shown_dir(&dir)),
            };
            self.log
                .action(format!("Making output directory for {what} {shown}"));
            self.dirs.insert(dir.clone());
        }
        let mut out = Written::default();
        if rows.is_empty() {
            self.log.action("No Data Found");
            return Ok(out);
        }
        let host = self.host;
        let utf8 = Encoding::export_csv_utf8(host.edition);
        if formats.csv {
            let rel = self.rel(prefix, user, "csv");
            let mut ev = DateEvidence::default();
            let (text, spans) = match self.csv_headers.get(&rel) {
                Some(header) if append => {
                    let r = export_csv_append(&host, header, rows, &mut ev);
                    (r.text, r.spans)
                }
                _ => {
                    let header: Vec<String> = rows[0].iter().map(|(k, _)| k.clone()).collect();
                    self.csv_headers.insert(rel.clone(), header);
                    let r = export_csv(&host, rows, &mut ev);
                    (r.text, r.spans)
                }
            };
            out.csv =
                Some(self.put(tree, &rel, utf8, &text, spans, append, notice, (art, user))?);
            if ev.culture_dates > 0 {
                tree.date_evidence(&rel, ev);
            }
        }
        if formats.txt {
            let rel = self.rel(prefix, user, "txt");
            let mut ev = DateEvidence::default();
            let r = format_list(&host, rows, &mut ev);
            let enc = Encoding::out_file_default(host.edition);
            out.txt = Some(self.put(
                tree,
                &rel,
                enc,
                &r.text,
                r.spans,
                append,
                notice,
                (art, user),
            )?);
            if ev.culture_dates > 0 {
                tree.date_evidence(&rel, ev);
            }
        }
        if formats.json {
            let rel = self.rel(prefix, user, "json");
            let r = convert_to_json(&host, rows, false);
            let text = format!("{}{}", r.text, host.newline);
            *self.json_docs.entry(rel.clone()).or_default() += 1;
            out.json = Some(self.put(
                tree,
                &rel,
                utf8,
                &text,
                r.spans,
                append,
                notice,
                (art, user),
            )?);
        }
        Ok(out)
    }

    /// The number of JSON documents written to `rel` so far.
    pub fn json_documents(&self, rel: &str) -> u32 {
        self.json_docs.get(rel).copied().unwrap_or(0)
    }

    fn shown_dir(&self, dir: &str) -> String {
        if self.non_windows {
            format!("{}/{dir}", self.file_path)
        } else {
            format!("{}\\{}", self.file_path, dir.trim_start_matches('\\'))
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn put(
        &mut self,
        tree: &mut Tree<'_>,
        rel: &str,
        encoding: Encoding,
        text: &str,
        spans: Vec<(u32, u32)>,
        append: bool,
        notice: bool,
        (art, subject): (Art, Option<&str>),
    ) -> Result<Part> {
        let (dir, file) = rel.rsplit_once('/').unwrap_or(("", rel));
        let shown = self.shown(dir, file);
        if append {
            self.log.plain(format!("Appending Data to {shown}"));
        } else {
            self.log.action(format!("Writing Data to {shown}"));
        }
        let before = tree.write(&spec(rel, encoding, art, subject), text)?;
        if notice {
            self.log.silent_notice(&shown);
        }
        Ok(Part {
            rel: rel.to_string(),
            spans: spans
                .into_iter()
                .map(|(a, b)| (a + before, b + before))
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declarations_carry_artifact_derived_flag_and_subject() {
        let s = spec(
            "ann@contoso.example/Simple_User_Changes_ann.json",
            Encoding::Utf8,
            Art::derived("hawk.user.simple_ual"),
            Some("ann@contoso.example"),
        );
        assert_eq!(s.artifact, Some("hawk.user.simple_ual"));
        assert!(s.derived);
        assert_eq!(s.subject.as_deref(), Some("ann@contoso.example"));
        assert_eq!(s.expect_status, None);
        let s = spec(
            "x.msg/Message_Header_x.msg.csv",
            Encoding::Utf8,
            Art::not_supported("hawk.message.header"),
            Some("x.msg"),
        );
        assert_eq!(s.expect_status, Some("not_supported"));
    }

    #[test]
    #[should_panic(expected = "declared parsed")]
    fn a_parsed_declaration_of_an_unparsed_artifact_panics() {
        spec(
            "x.msg/Message_Header_x.msg.csv",
            Encoding::Utf8,
            Art::raw("hawk.message.header"),
            None,
        );
    }
}
