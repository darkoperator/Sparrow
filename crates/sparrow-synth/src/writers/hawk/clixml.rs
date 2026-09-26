//! `Export-Clixml`, as Hawk 3.1's `Out-MultipleFileType -xml` writes it into `Tenant/XML/`
//! (research hawk layouts §7.1, capture survey §2b): an `<Objs>` document in the PowerShell
//! serialization namespace with one `<Obj>` per object, its type names in `<TN>` (a `<TNRef>`
//! after the first object) and every property as a string `<S N="...">` in `<MS>` (null as
//! `<Nil N="..." />`). Minimal on purpose: Sparrow records these copies of the CSV/JSON content
//! without parsing them. Windows PowerShell 5.1 writes UTF-16LE with a byte-order mark,
//! PowerShell 7 UTF-8.

use crate::options::PsEdition;
use crate::ps::{Encoding, Host, Row, Val, csv_imported};

/// The PowerShell serialization namespace (a product constant, `reserved::WELL_KNOWN_URLS`).
pub const NAMESPACE: &str = "http://schemas.microsoft.com/powershell/2004/04";

/// The type names every exported object carries (deserialized custom objects).
const TYPE_NAMES: [&str; 2] = [
    "Deserialized.System.Management.Automation.PSCustomObject",
    "Deserialized.System.Object",
];

/// `Export-Clixml`'s encoding on `edition`.
pub fn encoding(edition: PsEdition) -> Encoding {
    match edition {
        PsEdition::Ps51 => Encoding::Utf16LeBom,
        PsEdition::Ps7 => Encoding::Utf8,
    }
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\r' => out.push_str("_x000D_"),
            '\n' => out.push_str("_x000A_"),
            other => out.push(other),
        }
    }
    out
}

/// The CliXml document of `rows` as `host` writes it (line ends `host.newline`, trailing one).
pub fn render(host: &Host, rows: &[Row]) -> String {
    let nl = host.newline;
    let mut out = format!("<Objs Version=\"1.1.0.1\" xmlns=\"{NAMESPACE}\">{nl}");
    for (i, row) in rows.iter().enumerate() {
        out.push_str(&format!("  <Obj RefId=\"{i}\">{nl}"));
        if i == 0 {
            out.push_str(&format!("    <TN RefId=\"0\">{nl}"));
            for t in TYPE_NAMES {
                out.push_str(&format!("      <T>{t}</T>{nl}"));
            }
            out.push_str(&format!("    </TN>{nl}"));
        } else {
            out.push_str(&format!("    <TNRef RefId=\"0\" />{nl}"));
        }
        out.push_str(&format!("    <MS>{nl}"));
        for ((k, v), (_, text)) in row.iter().zip(csv_imported(host, row)) {
            let name = escape(k);
            match (v, text) {
                (Val::Null, _) => out.push_str(&format!("      <Nil N=\"{name}\" />{nl}")),
                (_, Val::Str(t)) => {
                    out.push_str(&format!("      <S N=\"{name}\">{}</S>{nl}", escape(&t)))
                }
                (_, _) => out.push_str(&format!("      <Nil N=\"{name}\" />{nl}")),
            }
        }
        out.push_str(&format!("    </MS>{nl}"));
        out.push_str(&format!("  </Obj>{nl}"));
    }
    out.push_str(&format!("</Objs>{nl}"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::options::Culture;

    #[test]
    fn objects_carry_type_names_and_string_properties() {
        let host = Host::new(PsEdition::Ps51, Culture::EnUs, 0);
        let rows = vec![
            vec![
                ("Name".to_string(), Val::Str("a <b> & c".into())),
                ("Enabled".to_string(), Val::Bool(true)),
                ("Note".to_string(), Val::Null),
            ],
            vec![("Name".to_string(), Val::Str("d".into()))],
        ];
        let text = render(&host, &rows);
        assert!(text.starts_with(
            "<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\">\r\n"
        ));
        assert!(text.contains("<S N=\"Name\">a &lt;b&gt; &amp; c</S>"));
        assert!(text.contains("<S N=\"Enabled\">True</S>"));
        assert!(text.contains("<Nil N=\"Note\" />"));
        assert!(text.contains("<TNRef RefId=\"0\" />"));
        assert_eq!(text.matches("<Obj RefId=").count(), 2);
        assert!(text.ends_with("</Objs>\r\n"));
    }
}
