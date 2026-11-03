//! Writes a large, recognisable evidence file for ingest memory tests.
//!
//! cargo run -p sparrow-synth --release --example big_file -- \
//!   --kind <portal-ual|ual-json|signins-csv|message-trace-detail> --bytes <N> \
//!   --encoding <utf8|utf8bom|utf16le> --out <file>
//!
//! `ual-json` is only classified when `--out` sits under
//! `UnifiedAuditLog/<yyyymmdd-hhmmss>/Merged/UAL-Combined.json`.

use sparrow_synth::big_file::{BigEncoding, BigKind, write_big_file};
use std::path::PathBuf;

fn main() {
    let (mut kind, mut bytes, mut enc, mut out) = (None, None, BigEncoding::Utf8, None);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let v = args
            .next()
            .unwrap_or_else(|| die(&format!("{a} needs a value")));
        match a.as_str() {
            "--kind" => kind = BigKind::parse(&v),
            "--bytes" => bytes = v.parse::<u64>().ok(),
            "--encoding" => {
                enc = BigEncoding::parse(&v).unwrap_or_else(|| die("bad --encoding"));
            }
            "--out" => out = Some(PathBuf::from(v)),
            _ => die(&format!("unknown argument {a}")),
        }
    }
    let (Some(kind), Some(bytes), Some(out)) = (kind, bytes, out) else {
        die("--kind, --bytes and --out are required");
    };
    match write_big_file(kind, bytes, enc, &out) {
        Ok(n) => println!("{n}"),
        Err(e) => die(&e.to_string()),
    }
}

fn die(msg: &str) -> ! {
    eprintln!("big_file: {msg}");
    std::process::exit(2);
}
