//! What to generate: the collector, the PowerShell edition and host culture that wrote the
//! files, and collector-specific variants.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

macro_rules! text_enum {
    ($name:ident { $($variant:ident => $text:literal $(| $alias:literal)*),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub enum $name {
            $(#[serde(rename = $text)] $variant),+
        }
        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$variant),+];
            pub fn as_str(self) -> &'static str {
                match self { $($name::$variant => $text),+ }
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
        impl FromStr for $name {
            type Err = String;
            fn from_str(s: &str) -> Result<Self, String> {
                let l = s.trim().to_ascii_lowercase();
                $(if l == $text.to_ascii_lowercase() $(|| l == $alias)* { return Ok($name::$variant); })+
                Err(format!(
                    "unknown {} '{s}'; expected one of: {}",
                    stringify!($name),
                    [$($text),+].join(", ")
                ))
            }
        }
    };
}

text_enum!(Collector {
    Hawk3 => "hawk3",
    Hawk4 => "hawk4",
    Invictus => "invictus" | "microsoft-extractor-suite",
    Portal => "portal",
});

text_enum!(PsEdition { Ps51 => "5.1" | "ps51", Ps7 => "7" | "ps7" });

text_enum!(Culture { EnUs => "en-US", EnGb => "en-GB", DeDe => "de-DE", JaJp => "ja-JP" });

// Microsoft-Extractor-Suite Get-UAL -Output (and -AuditDataOnly) variants.
text_enum!(UalFormat {
    Csv => "csv",
    CsvAuditDataOnly => "csv-auditdataonly",
    Json => "json",
    JsonAuditDataOnly => "json-auditdataonly",
    SofElk => "sof-elk",
    Jsonl => "jsonl",
});

// How the analyst saved the Entra portal sign-in export.
text_enum!(SigninExport { Csv => "csv", Xlsx => "xlsx" });

/// Everything that selects one rendering of a scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerateOptions {
    pub collector: Collector,
    pub ps: PsEdition,
    pub culture: Culture,
    pub seed: u64,
    /// Microsoft-Extractor-Suite Get-UAL output format.
    pub ual_format: UalFormat,
    /// Portal Entra sign-in export file type.
    pub signin_export: SigninExport,
    /// Hawk 4: tenant files written by PowerShell 7, user files by Windows PowerShell 5.1
    /// (two sessions, as in the survey's capture D).
    pub hawk_mixed_editions: bool,
    /// PowerShell 7 on macOS/Linux: LF line ends; Hawk's literal `\Tenant` folder;
    /// Microsoft-Extractor-Suite's `Output\LogFile.txt` as one file name with a backslash.
    pub non_windows: bool,
    /// Microsoft-Extractor-Suite: write TenantLicenses.csv / UserLicenses.csv (Get-Licenses,
    /// Get-LicensesByUser); false reproduces the invictus sample (security defaults only).
    pub invictus_licence_list: bool,
    /// Microsoft-Extractor-Suite Get-Devices `-Output JSON`: the JSON goes into the `.csv`
    /// path (a bare object for one device, an array otherwise).
    #[serde(default)]
    pub invictus_devices_json: bool,
    /// Microsoft-Extractor-Suite: write a complete `CollectionManifest-<GUID>.mesmanifest` into
    /// each log run folder (UAL, sign-in, Entra audit). Off keeps every existing tree, digest and
    /// cache key unchanged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub invictus_manifests: bool,
    /// Scale overrides (Task 25): total benign UAL rows / sign-ins, replacing the scenario's.
    pub ual_rows: Option<u64>,
    pub signins: Option<u64>,
    /// Per-tree variants the seed otherwise picks (`None`: the seed's pick). `--real` conformance forces each in
    /// turn to compare a real capture with every variant a tree can take. Portal: the Purview `CreationDate`
    /// form (`true`: the host-culture form of the older export).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purview_culture_dates: Option<bool>,
    /// Portal: the message-trace summary re-saved through Excel (`true`: single-byte file).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_trace_excel_resave: Option<bool>,
    /// Hawk: the UAL `CreationDate` kind of the embedded raw records (`true`: UTC, `false`: unspecified).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hawk_ual_creation_utc: Option<bool>,
}

impl GenerateOptions {
    pub fn new(collector: Collector, seed: u64) -> Self {
        GenerateOptions {
            collector,
            ps: PsEdition::Ps7,
            culture: Culture::EnUs,
            seed,
            ual_format: UalFormat::Csv,
            signin_export: SigninExport::Csv,
            hawk_mixed_editions: false,
            non_windows: false,
            invictus_licence_list: true,
            invictus_devices_json: false,
            invictus_manifests: false,
            ual_rows: None,
            signins: None,
            purview_culture_dates: None,
            message_trace_excel_resave: None,
            hawk_ual_creation_utc: None,
        }
    }
}
