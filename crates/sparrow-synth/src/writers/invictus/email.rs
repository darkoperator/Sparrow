//! Get-Email (research event layouts §9): `Email Export/<ts>/<NNN>-<yyyyMMdd_HHmmss>-<subject>.eml`
//! for every `world.emails` message, and `Email Export/<ts>/Attachments/<...>` for a message with
//! an attachment. The MIME headers follow the raw Graph `$value` order; long headers are folded.

use super::Ctx;
use crate::Result;
use crate::keys;
use crate::story::Evidence;
use crate::tree::{FileSpec, Tree};
use crate::world::Email;
use std::fmt::Write as _;

/// The characters Windows forbids in a file name.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if "\\/:*?\"<>|".contains(c) { '_' } else { c })
        .collect()
}

/// Fold `Name: value` at 78 columns on spaces (continuation lines start with a space).
fn fold_header(name: &str, value: &str) -> String {
    let first = format!("{name}: {value}");
    if first.len() <= 78 {
        return first;
    }
    let mut lines: Vec<String> = Vec::new();
    let mut cur = format!("{name}:");
    for word in value.split(' ') {
        if cur.len() + 1 + word.len() > 78 && cur.len() > name.len() + 1 {
            lines.push(cur);
            cur = format!(" {word}");
        } else {
            cur.push(' ');
            cur.push_str(word);
        }
    }
    lines.push(cur);
    lines.join("\r\n")
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// The MIME text and the number of header-block lines (its record provenance).
fn mime(e: &Email) -> (String, u32) {
    let boundary = format!(
        "----=_NextPart_{}",
        e.message_id.trim_matches(['<', '>']).replace('@', "_")
    );
    let mut headers: Vec<(String, String)> = e
        .received
        .iter()
        .map(|r| ("Received".to_string(), r.clone()))
        .collect();
    let content_type = if e.attachment.is_some() {
        format!("multipart/mixed; boundary=\"{boundary}\"")
    } else {
        "text/plain; charset=\"utf-8\"".to_string()
    };
    headers.extend([
        ("Authentication-Results".into(), e.auth_results.clone()),
        ("Return-Path".into(), e.return_path.clone()),
        (
            "From".into(),
            format!("\"{}\" <{}>", e.from_display, e.from),
        ),
        ("To".into(), e.to.join(", ")),
        ("Subject".into(), e.subject.clone()),
        ("Date".into(), e.date.to_rfc2822()),
        ("Message-ID".into(), e.message_id.clone()),
        ("MIME-Version".into(), "1.0".into()),
        ("Content-Type".into(), content_type),
        (
            "X-MS-Exchange-Organization-AuthAs".into(),
            e.auth_as.clone(),
        ),
        (
            "X-MS-Exchange-Organization-AuthMechanism".into(),
            e.auth_mechanism.clone(),
        ),
        ("X-Originating-IP".into(), format!("[{}]", e.originating_ip)),
    ]);
    let mut text = String::new();
    for (name, value) in &headers {
        text.push_str(&fold_header(name, value));
        text.push_str("\r\n");
    }
    text.push_str("\r\n");
    let header_lines = text[..text.find("\r\n\r\n").unwrap_or(text.len())]
        .matches("\r\n")
        .count() as u32
        + 1;
    if let Some((filename, bytes)) = &e.attachment {
        let _ = write!(
            text,
            "--{boundary}\r\nContent-Type: text/plain; charset=\"utf-8\"\r\n\r\n{}",
            e.body
        );
        let _ = write!(text, "\r\n--{boundary}\r\n");
        let _ = write!(
            text,
            "Content-Type: application/octet-stream; name=\"{filename}\"\r\n"
        );
        text.push_str("Content-Transfer-Encoding: base64\r\n");
        let _ = write!(
            text,
            "Content-Disposition: attachment; filename=\"{filename}\"\r\n\r\n{}",
            base64_encode(bytes)
        );
        let _ = write!(text, "\r\n--{boundary}--\r\n");
    } else {
        text.push_str(&e.body);
    }
    (text, header_lines)
}

/// Get-Email: one `.eml` per message, plus its first attachment.
pub(super) fn write(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("Email Export", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log
        .add(run.local, "=== Starting Email Export Collection ===");
    if c.world.emails.is_empty() {
        return Ok(());
    }
    let attachments = format!("{dir}/Attachments");
    for (i, e) in c.world.emails.iter().enumerate() {
        let nnn = i + 1;
        let stamp = e.date.format("%Y%m%d_%H%M%S").to_string();
        let subject = sanitize(&e.subject);
        let rel = format!("{dir}/{nnn:03}-{stamp}-{subject}.eml");
        let (text, header_lines) = mime(e);
        tree.write(
            &FileSpec::new(&rel, Some("inv.email"), crate::ps::Encoding::Utf8),
            &text,
        )?;
        let key = keys::email(&e.message_id);
        tree.row(&rel, "email_artifacts", key);
        tree.deliver(
            &Evidence::Email(e.message_id.clone()),
            "email_artifacts",
            &rel,
            (1, header_lines),
        );
        if let Some((filename, bytes)) = &e.attachment {
            tree.dir(&attachments)?;
            let rel = format!("{attachments}/{stamp}-{subject}-{}", sanitize(filename));
            tree.write_bytes(
                &FileSpec::new(
                    &rel,
                    Some("inv.email.attachment"),
                    crate::ps::Encoding::Utf8,
                ),
                bytes,
            )?;
        }
    }
    Ok(())
}
