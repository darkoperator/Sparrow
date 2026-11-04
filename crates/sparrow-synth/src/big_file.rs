//! Multi-gigabyte evidence files for memory and throughput tests of the streaming ingest.
//!
//! One template record per kind is varied row by row (unique id, increasing time), so a file of
//! any size classifies as its artifact and loads every row. Written in a streaming fashion: the
//! memory used does not depend on the size asked for. Nothing here comes from a real capture.

use crate::error::{Error, Result};
use crate::writers::portal::SIGNIN_HEADERS;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

/// Which artifact the file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BigKind {
    /// Purview audit search CSV (`portal.ual`).
    PortalUal,
    /// Extractor-Suite `UAL-Combined.json` (`inv.ual.merged`); the file must sit under
    /// `UnifiedAuditLog/<yyyymmdd-hhmmss>/Merged/` to be classified, see [`BigKind::example_rel_path`].
    UalJson,
    /// Entra sign-ins portal CSV (`portal.entra_signins`).
    SigninsCsv,
    /// Exchange admin center message trace detail CSV (`portal.message_trace_detail`).
    MessageTraceDetail,
}

impl BigKind {
    pub const ALL: [BigKind; 4] = [
        BigKind::PortalUal,
        BigKind::UalJson,
        BigKind::SigninsCsv,
        BigKind::MessageTraceDetail,
    ];

    pub fn parse(s: &str) -> Option<BigKind> {
        Some(match s {
            "portal-ual" => BigKind::PortalUal,
            "ual-json" => BigKind::UalJson,
            "signins-csv" => BigKind::SigninsCsv,
            "message-trace-detail" => BigKind::MessageTraceDetail,
            _ => return None,
        })
    }

    /// A path under a collection root where the file is classified as its artifact.
    pub fn example_rel_path(self) -> &'static str {
        match self {
            BigKind::PortalUal => "big_ual.csv",
            BigKind::UalJson => {
                "Contoso_Example/UnifiedAuditLog/20260101-000000/Merged/UAL-Combined.json"
            }
            BigKind::SigninsCsv => "InteractiveSignIns_2026-01-01_2026-01-31.csv",
            BigKind::MessageTraceDetail => "MTDetail_big.csv",
        }
    }
}

/// The file's text encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BigEncoding {
    Utf8,
    Utf8Bom,
    Utf16Le,
}

impl BigEncoding {
    pub fn parse(s: &str) -> Option<BigEncoding> {
        Some(match s {
            "utf8" => BigEncoding::Utf8,
            "utf8bom" => BigEncoding::Utf8Bom,
            "utf16le" => BigEncoding::Utf16Le,
            _ => return None,
        })
    }
}

/// Encodes text as it goes to the file and counts the bytes written.
struct Sink<W: Write> {
    w: BufWriter<W>,
    enc: BigEncoding,
    written: u64,
}

impl<W: Write> Sink<W> {
    fn new(w: W, enc: BigEncoding) -> Result<Sink<W>> {
        let mut s = Sink {
            w: BufWriter::with_capacity(1 << 20, w),
            enc,
            written: 0,
        };
        match enc {
            BigEncoding::Utf8 => {}
            BigEncoding::Utf8Bom => s.raw(&[0xEF, 0xBB, 0xBF])?,
            BigEncoding::Utf16Le => s.raw(&[0xFF, 0xFE])?,
        }
        Ok(s)
    }

    fn raw(&mut self, b: &[u8]) -> Result<()> {
        self.w
            .write_all(b)
            .map_err(|e| Error::Invalid(format!("write: {e}")))?;
        self.written += b.len() as u64;
        Ok(())
    }

    fn text(&mut self, t: &str) -> Result<()> {
        if self.enc == BigEncoding::Utf16Le {
            let mut buf = Vec::with_capacity(t.len() * 2);
            for u in t.encode_utf16() {
                buf.extend_from_slice(&u.to_le_bytes());
            }
            self.raw(&buf)
        } else {
            self.raw(t.as_bytes())
        }
    }

    fn finish(mut self) -> Result<u64> {
        self.w
            .flush()
            .map_err(|e| Error::Invalid(format!("flush: {e}")))?;
        Ok(self.written)
    }
}

/// A unique, deterministic v4-shaped GUID for row `i`.
fn guid(salt: u32, i: u64) -> String {
    format!(
        "{:08x}-{:04x}-4{:03x}-8{:03x}-{:012x}",
        salt,
        (i >> 48) & 0xffff,
        (i >> 36) & 0xfff,
        (i >> 24) & 0xfff,
        i & 0xffff_ffff_ffff
    )
}

/// Row `i`'s time: 2026-01-01T00:00:00Z plus `i` seconds, as (date, time) text.
fn stamp(i: u64) -> (String, String) {
    let t = chrono::DateTime::from_timestamp(1_767_225_600 + i as i64, 0).expect("in range");
    (
        t.format("%Y-%m-%d").to_string(),
        t.format("%H:%M:%S").to_string(),
    )
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// The audit record of one row (about 1 KB); `{ID}` and `{TIME}` are filled per row.
const AUDIT_TEMPLATE: &str = r#"{"CreationTime":"{TIME}","Id":"{ID}","Operation":"MailItemsAccessed","OrganizationId":"d5c9185c-9bf3-45a3-92f3-c19c635feb78","RecordType":50,"ResultStatus":"Succeeded","UserKey":"10032000261B9FBE","UserType":0,"Version":1,"Workload":"Exchange","ClientIP":"198.51.100.7","UserId":"rowan.porter@contoso.example","AppAccessContext":{"AADSessionId":"91287f35-20a5-41b2-9864-29bdab35935d","ClientAppId":"d3590ed6-52b3-4102-aeff-aad2292ab01c","ClientAppName":"Microsoft Office","CorrelationId":"9321398a-beb8-4fb6-b51a-90006a741198","IssuedAtTime":"2026-01-01T00:00:00","UniqueTokenId":"qGVaHZdrSlmzoqdnF-kJ9I"},"ClientAppId":"d3590ed6-52b3-4102-aeff-aad2292ab01c","ClientIPAddress":"198.51.100.7","ClientInfoString":"Client=MSExchangeRPC","ActorInfoString":"Client=MSExchangeRPC","ClientProcessName":"OUTLOOK.EXE","ClientRequestId":"3af9851e-b7ce-49f6-a7f3-c48a161e073d","ClientVersion":"16.0.17928.20114","HostAppId":"d3590ed6-52b3-4102-aeff-aad2292ab01c","TokenObjectId":"d6e9762f-d177-4879-a1a1-fbb0bbde3a25","TokenTenantId":"d5c9185c-9bf3-45a3-92f3-c19c635feb78","ExternalAccess":false,"InternalLogonType":0,"LogonType":0,"LogonUserSid":"S-1-5-21-737835370-1108084686-5515698059-1501","MailboxGuid":"ffb0d2e9-9d3b-4503-a2cc-2d3a5f1b8a10","MailboxOwnerSid":"S-1-5-21-737835370-1108084686-5515698059-1501","MailboxOwnerUPN":"rowan.porter@contoso.example","OrganizationName":"contoso.onmicrosoft.example","OriginatingServer":"BGX0PR70MB8393","SessionId":"91287f35-20a5-41b2-9864-29bdab35935d","OperationProperties":[{"Name":"MailAccessType","Value":"Bind"},{"Name":"IsThrottled","Value":"False"}],"Folders":[{"Path":"\\Inbox","FolderItems":[{"Id":"RgAAAAAntxQAAuUWmkQdxd+EiOCEBeOoCLKCDYep22OPX0ocRdT5xX75uE5gGG5KYv8jm8jvvEBqP24uLYK+UFURcQdRWBkfiR5LWsjMLyZAAAJ","InternetMessageId":"<886F5ADB51D1CDFF@contoso.example>"}]}]}"#;

/// A unique v4-shaped GUID for row `i` whose every field looks random: the first field holds the high half of
/// `mix(i)` (salted), the last its low 48 bits, so distinct rows keep distinct ids.
fn scattered_guid(salt: u32, i: u64) -> String {
    let m = mix(i);
    let n = mix(m);
    format!(
        "{:08x}-{:04x}-4{:03x}-8{:03x}-{:012x}",
        (m >> 32) as u32 ^ salt,
        n & 0xffff,
        (n >> 16) & 0xfff,
        (n >> 28) & 0xfff,
        m & 0xffff_ffff_ffff
    )
}

/// The splitmix64 finalizer: a bijection of `u64`, so distinct rows keep distinct ids.
fn mix(i: u64) -> u64 {
    let mut z = i.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn audit(i: u64, id: &str) -> String {
    let (d, t) = stamp(i);
    AUDIT_TEMPLATE
        .replace("{ID}", id)
        .replace("{TIME}", &format!("{d}T{t}"))
}

/// Writes rows from `row(first)`, `row(first + 1)`, ... until at least `bytes` were written.
fn write_rows<W: Write>(
    sink: &mut Sink<W>,
    bytes: u64,
    first: u64,
    sep_first: &str,
    sep: &str,
    row: impl Fn(u64) -> String,
) -> Result<()> {
    let mut i = 0u64;
    while sink.written < bytes || i == 0 {
        let r = row(first + i);
        if i == 0 {
            sink.text(sep_first)?;
        } else {
            sink.text(sep)?;
        }
        sink.text(&r)?;
        i += 1;
    }
    Ok(())
}

/// Where a file's rows start and how their ids look.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BigOptions {
    /// Index of the first row: rows `first..` get the ids and times of those indexes, so files written with
    /// disjoint ranges hold disjoint records (and differ in content).
    pub first: u64,
    /// Spread the ids over the whole GUID space (a bijective mix of the row index) instead of counting up, as
    /// real record ids are: an index on them is then inserted into at random places, not appended to.
    pub scatter_ids: bool,
}

/// Writes a file of `kind` of at least `bytes` bytes (one row past the mark) to `out`, creating
/// its parent directories; returns the bytes written. The file is whole when the call returns.
pub fn write_big_file(kind: BigKind, bytes: u64, encoding: BigEncoding, out: &Path) -> Result<u64> {
    write_big_file_with(kind, bytes, encoding, out, BigOptions::default())
}

/// [`write_big_file`] with the rows starting at `opts.first` and the ids as `opts.scatter_ids` says.
pub fn write_big_file_with(
    kind: BigKind,
    bytes: u64,
    encoding: BigEncoding,
    out: &Path,
    opts: BigOptions,
) -> Result<u64> {
    let guid = |salt: u32, i: u64| {
        if opts.scatter_ids {
            scattered_guid(salt, i)
        } else {
            guid(salt, i)
        }
    };
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    let f = File::create(out).map_err(|e| Error::io(out, e))?;
    let mut sink = Sink::new(f, encoding)?;
    match kind {
        BigKind::PortalUal => {
            sink.text("RecordId,CreationDate,RecordType,Operation,UserId,AuditData,AssociatedAdminUnits,AssociatedAdminUnitsNames\r\n")?;
            write_rows(&mut sink, bytes, opts.first, "", "", |i| {
                let (d, t) = stamp(i);
                format!(
                    "{},{d}T{t}.0000000Z,50,MailItemsAccessed,rowan.porter@contoso.example,{},,\r\n",
                    guid(0xa0d1, i),
                    csv_field(&audit(i, &guid(0xa0d1, i))),
                )
            })?;
        }
        BigKind::UalJson => {
            sink.text("[\n")?;
            write_rows(&mut sink, bytes, opts.first, "", ",\n", |i| {
                let (d, t) = stamp(i);
                format!(
                    "{{\n    \"RecordType\": \"ExchangeItemGroup\",\n    \"CreationDate\": \"{d}T{t}Z\",\n    \"UserIds\": \"rowan.porter@contoso.example\",\n    \"Operations\": \"MailItemsAccessed\",\n    \"AuditData\": {}\n}}",
                    audit(i, &guid(0xa0d1, i))
                )
            })?;
            sink.text("\n]\n")?;
        }
        BigKind::SigninsCsv => {
            let header: Vec<String> = SIGNIN_HEADERS.iter().map(|h| csv_field(h)).collect();
            sink.text(&header.join(","))?;
            sink.text("\n")?;
            write_rows(&mut sink, bytes, opts.first, "", "", |i| {
                let (d, t) = stamp(i);
                format!(
                    "{d}T{t}Z,{},\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\",{},b086bc34-4d29-464b-85de-b1f53d90a0dd,Kelly Chambers,kelly.chambers@contoso.example,Member,None,none,None,yugsJoSyD6a1yx1OZZUZdd,None,None,Unbound,,OfficeHome,4765445b-32c6-49b0-83e6-1d93765276ca,f8cdef31-a31e-4b4a-93e4-5f571e91255a,Office 365 SharePoint Online,00000003-0000-0ff1-ce00-000000000000,d5c9185c-9bf3-45a3-92f3-c19c635feb78,f8cdef31-a31e-4b4a-93e4-5f571e91255a,d5c9185c-9bf3-45a3-92f3-c19c635feb78,,192.0.2.13,\"Northbridge, NB, US\",Success,,,Browser,d91cd7d9-46ec-46e6-af9d-f57f0b701016,Chrome,Windows 11,Yes,Yes,Azure AD joined,,,,Single-factor authentication,kelly.chambers@contoso.example,{},192.0.2.13,No,,64496,No,AzureAD,none,,326,Not Applied,,,,\n",
                    guid(0xb1e2, i),
                    guid(0xc3f4, i),
                    guid(0xd405, i),
                )
            })?;
        }
        BigKind::MessageTraceDetail => {
            sink.text("date_time_utc,network_message_id,internal_message_id,message_id,event_id,source,source_context,sender_address,recipient_address,related_recipient_address,recipient_status,client_ip,client_hostname,server_ip,server_hostname,original_client_ip,original_server_ip,connector_id,total_bytes,recipient_count,reference,message_subject,return_path,message_info,directionality,tenant_id,custom_data\r\n")?;
            write_rows(&mut sink, bytes, opts.first, "", "", |i| {
                let (d, t) = stamp(i);
                format!(
                    "{d}T{t}.000Z,{},{},<{}@contoso.example>,RECEIVE,SMTP,\"Message received from connector\",sender@fabrikam.example,kelly.chambers@contoso.example,,\"250 2.1.5 Recipient OK\",203.0.113.5,mail.fabrikam.example,198.51.100.20,mail.contoso.example,203.0.113.5,198.51.100.20,Inbound from Internet,4096,1,,Quarterly report {i},sender@fabrikam.example,,Incoming,d5c9185c-9bf3-45a3-92f3-c19c635feb78,\"S:AccountForest=contoso.example\"\r\n",
                    guid(0xe516, i),
                    i + 1,
                    guid(0xf627, i),
                )
            })?;
        }
    }
    sink.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sparrow_core::Case;
    use sparrow_core::discovery::{Registry, Tool};
    use sparrow_core::ingest::parser::ParserRegistry;
    use sparrow_core::ingest::{IngestOptions, ingest_path};

    fn tool(kind: BigKind) -> Tool {
        match kind {
            BigKind::UalJson => Tool::Invictus,
            _ => Tool::PortalExport,
        }
    }

    fn expected(kind: BigKind) -> (&'static str, &'static str) {
        match kind {
            BigKind::PortalUal => ("portal.ual", "ual_events"),
            BigKind::UalJson => ("inv.ual.merged", "ual_events"),
            BigKind::SigninsCsv => ("portal.entra_signins", "signins"),
            BigKind::MessageTraceDetail => ("portal.message_trace_detail", "message_trace_events"),
        }
    }

    #[test]
    fn every_kind_classifies_and_loads() {
        for kind in BigKind::ALL {
            let dir = tempfile::tempdir().unwrap();
            let out = dir.path().join(kind.example_rel_path());
            let n = write_big_file(kind, 2_000_000, BigEncoding::Utf8, &out).unwrap();
            assert!(n >= 2_000_000, "{kind:?}: wrote {n}");
            assert_eq!(std::fs::metadata(&out).unwrap().len(), n);
            let rel = kind.example_rel_path();
            let c = Registry::builtin()
                .classify_file(tool(kind), rel, &out)
                .unwrap_or_else(|| panic!("{kind:?} is not classified"));
            let (artifact, target) = expected(kind);
            assert_eq!(c.artifact_id, artifact, "{kind:?}");
            assert_eq!(c.target, target, "{kind:?}");

            // The parser must load the rows, not reject them.
            let mut case = Case::in_memory().unwrap();
            let opts = IngestOptions {
                max_file_bytes: None,
                ..IngestOptions::default()
            };
            ingest_path(&mut case, dir.path(), &ParserRegistry::builtin(), &opts)
                .unwrap_or_else(|e| panic!("{kind:?}: ingest failed: {e}"));
            let rows: i64 = case
                .conn()
                .query_row(&format!("SELECT count(*) FROM {target}"), [], |r| r.get(0))
                .unwrap();
            let errors: i64 = case
                .conn()
                .query_row("SELECT count(*) FROM parse_errors", [], |r| r.get(0))
                .unwrap();
            assert!(rows > 500, "{kind:?}: only {rows} rows loaded");
            assert_eq!(errors, 0, "{kind:?}: parse errors");
        }
    }

    #[test]
    fn encodings_start_with_their_marker_and_load() {
        for (enc, marker) in [
            (BigEncoding::Utf8Bom, vec![0xEF, 0xBB, 0xBF]),
            (BigEncoding::Utf16Le, vec![0xFF, 0xFE]),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let out = dir.path().join("big_ual.csv");
            write_big_file(BigKind::PortalUal, 300_000, enc, &out).unwrap();
            let bytes = std::fs::read(&out).unwrap();
            assert!(bytes.starts_with(&marker), "{enc:?}");
            let mut case = Case::in_memory().unwrap();
            ingest_path(
                &mut case,
                dir.path(),
                &ParserRegistry::builtin(),
                &IngestOptions::default(),
            )
            .unwrap_or_else(|e| panic!("{enc:?}: {e}"));
            let rows: i64 = case
                .conn()
                .query_row("SELECT count(*) FROM ual_events", [], |r| r.get(0))
                .unwrap();
            assert!(rows > 30, "{enc:?}: {rows} rows");
        }
    }

    #[test]
    fn row_ids_are_unique() {
        let ids: std::collections::HashSet<String> = (0..10_000).map(|i| guid(1, i)).collect();
        assert_eq!(ids.len(), 10_000);
        let mixed: std::collections::HashSet<String> =
            (0..10_000).map(|i| scattered_guid(1, i)).collect();
        assert_eq!(mixed.len(), 10_000);
    }

    /// Two files written with disjoint `first` ranges and scattered ids load as disjoint records, ids spread out.
    #[test]
    fn files_from_disjoint_ranges_hold_disjoint_scattered_records() {
        let dir = tempfile::tempdir().unwrap();
        let opts = |first| BigOptions {
            first,
            scatter_ids: true,
        };
        write_big_file_with(
            BigKind::PortalUal,
            300_000,
            BigEncoding::Utf8,
            &dir.path().join("a.csv"),
            opts(0),
        )
        .unwrap();
        write_big_file_with(
            BigKind::PortalUal,
            300_000,
            BigEncoding::Utf8,
            &dir.path().join("b.csv"),
            opts(1_000),
        )
        .unwrap();
        let mut case = Case::in_memory().unwrap();
        ingest_path(
            &mut case,
            dir.path(),
            &ParserRegistry::builtin(),
            &IngestOptions::default(),
        )
        .unwrap();
        let (rows, distinct, files, first_ids): (i64, i64, i64, i64) = case
            .conn()
            .query_row(
                "SELECT count(*), count(DISTINCT record_id),
                        (SELECT count(*) FROM source_files WHERE status = 'parsed'),
                        count(*) FILTER (WHERE CAST(record_id AS VARCHAR) LIKE '0000a0d1%')
                 FROM ual_events",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(files, 2);
        assert!(rows > 200, "{rows} rows");
        assert_eq!(distinct, rows, "every row its own record");
        // Counting ids all start with the salt; scattered ones (almost) never do.
        assert!(first_ids < 2, "{first_ids} ids start with the salt");
    }
}
