//! Builder of synthetic Microsoft-Extractor-Suite collection manifests (`CollectionManifest-<GUID>.mesmanifest`),
//! shaped like the fork's `Save-CollectionManifest` output. Synthetic data only.

#![allow(dead_code)]

use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};

/// A collection root holding a `LogFile.txt`, so it is discovered as a Microsoft-Extractor-Suite collection.
pub fn invictus_dir(tmp: &Path) -> PathBuf {
    let root = tmp.join("CASE_OUTPUT");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("LogFile.txt"),
        "2026-09-10 10:00:00: [INFO] Starting\n",
    )
    .unwrap();
    root
}

static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// A fresh, unique GUID text (process id, counter and clock; no random source needed).
fn fresh_guid() -> String {
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u128;
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    uuid::Uuid::from_u128((t << 40) ^ (u128::from(std::process::id()) << 72) ^ n).to_string()
}

/// A manifest under construction.
pub struct M {
    doc: Value,
}

impl M {
    /// A run with a fresh GUID `run_id`, schema v1, tool version 4.1.0.1 and no units.
    pub fn run(cmdlet: &str, status: &str) -> M {
        M {
            doc: json!({
                "schema": "mes-collection-manifest/1",
                "run_id": fresh_guid(),
                "tool": "Microsoft-Extractor-Suite",
                "tool_version": "4.1.0.1",
                "fork": "darkoperator/sparrow-gap-fixes",
                "cmdlet": cmdlet,
                "parameters": {},
                "started_utc": "2026-09-10T10:00:00Z",
                "finished_utc": "2026-09-10T11:00:00Z",
                "status": status,
                "throttle_waits": { "count": 0, "total_seconds": 0.0 },
                "units": [],
            }),
        }
    }

    /// A copy with the same run id and content.
    pub fn clone_doc(&self) -> M {
        M {
            doc: self.doc.clone(),
        }
    }

    pub fn run_id(&self) -> String {
        self.doc["run_id"].as_str().unwrap().to_string()
    }

    /// Set any top-level field (for example `schema`, or `run_id` to force a clash).
    pub fn set(mut self, k: &str, v: Value) -> M {
        self.doc[k] = v;
        self
    }

    pub fn param(mut self, k: &str, v: Value) -> M {
        self.doc["parameters"][k] = v;
        self
    }

    pub fn unit(mut self, u: U) -> M {
        let n = self.doc["units"].as_array().unwrap().len() + 1;
        let mut unit = u.unit;
        unit["unit_id"] = json!(format!("u-{n:04}"));
        self.doc["units"].as_array_mut().unwrap().push(unit);
        self
    }

    /// The manifest as the writer would save it.
    pub fn json(&self) -> String {
        serde_json::to_string_pretty(&self.doc).unwrap()
    }

    /// Write `<dir>/<Cmdlet folder>/CollectionManifest-<run_id>.mesmanifest`.
    pub fn write(&self, collection_dir: &Path) -> PathBuf {
        let cmdlet = self.doc["cmdlet"].as_str().unwrap_or("Cmdlet");
        let folder = cmdlet.strip_prefix("Get-").unwrap_or(cmdlet);
        write_text(collection_dir, folder, &self.run_id(), &self.json())
    }
}

/// Write `text` as the manifest of `run_id` in `<dir>/<folder>/`.
pub fn write_text(collection_dir: &Path, folder: &str, run_id: &str, text: &str) -> PathBuf {
    let dir = collection_dir.join(folder);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("CollectionManifest-{run_id}.mesmanifest"));
    std::fs::write(&path, text).unwrap();
    path
}

/// A unit under construction (a source x scope x time range and its outcome).
pub struct U {
    unit: Value,
}

impl U {
    pub fn new(sources: &[&str], start: &str, end: &str, state: &str) -> U {
        U {
            unit: json!({
                "unit_id": "u-0000",
                "sources": sources,
                "scope": {
                    "user_ids": null, "operations": null, "record_types": null, "ip_addresses": null,
                    "session_ids": null, "event_type": null, "direction": null, "other_filters": null
                },
                "start_utc": start,
                "end_utc": end,
                "state": state,
                "records_written": 0,
                "output_written": true,
                "files": [],
                "gaps": [],
            }),
        }
    }

    fn scope(mut self, k: &str, v: Value) -> U {
        self.unit["scope"][k] = v;
        self
    }

    pub fn users(self, u: &[&str]) -> U {
        self.scope("user_ids", json!(u))
    }

    pub fn operations(self, o: &[&str]) -> U {
        self.scope("operations", json!(o))
    }

    pub fn ips(self, i: &[&str]) -> U {
        self.scope("ip_addresses", json!(i))
    }

    pub fn direction(self, d: &str) -> U {
        self.scope("direction", json!(d))
    }

    /// An `other_filters` entry (created as an object on first use).
    pub fn other(mut self, k: &str, v: Value) -> U {
        if !self.unit["scope"]["other_filters"].is_object() {
            self.unit["scope"]["other_filters"] = Value::Object(Map::new());
        }
        self.unit["scope"]["other_filters"][k] = v;
        self
    }

    /// Set `other_filters` to an empty object (the writer's output for no extra filters).
    pub fn empty_other_filters(self) -> U {
        self.scope("other_filters", json!({}))
    }

    pub fn records(mut self, n: i64, file: &str) -> U {
        self.unit["records_written"] = json!(n);
        self.unit["files"] = json!([file]);
        self
    }

    pub fn output_written(mut self, b: bool) -> U {
        self.unit["output_written"] = json!(b);
        self
    }

    pub fn gap(mut self, start: &str, end: &str, reason: &str) -> U {
        self.unit["gaps"].as_array_mut().unwrap().push(json!({
            "start_utc": start, "end_utc": end, "reason": reason,
            "detail": null, "attempts": null, "records_in_window": null, "search_id": null
        }));
        self
    }

    /// Set a field of the last gap (for example `detail`, `attempts`).
    pub fn gap_field(mut self, k: &str, v: Value) -> U {
        let gaps = self.unit["gaps"].as_array_mut().unwrap();
        gaps.last_mut().expect("a gap first")[k] = v;
        self
    }

    /// On the last gap.
    pub fn search_id(self, id: &str) -> U {
        self.gap_field("search_id", json!(id))
    }
}
