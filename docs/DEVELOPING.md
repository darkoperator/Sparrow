# Developer notes

This page holds implementation and test detail moved out of the investigator-facing [README](../README.md). The full [reference](REFERENCE.md) preserves the collector, profile, detection, and synthetic-data sections of the original README. For the rule schema and authoring workflow, see [rules/README.md](../rules/README.md); for scenario and manifest formats, see [sparrow-synth/README.md](../crates/sparrow-synth/README.md).

## Inputs and normalization

- Hawk 3.x/4.x collections are discovered by content (`Hawk.log`, a `Tenant` directory, or user directories with known Hawk files), not the root name. Invictus 4.x Output roots comprise component/run directories; one root is a collection even with multiple runs and no `LogFile.txt`. Portal Purview audit, Entra sign-in CSV/XLSX, and Exchange message-trace exports are recognized by header, including in portal-only folders.
- Unified audit logs from raw, expanded, `Simple_*`, Purview, and Invictus Get-UAL CSV/JSON/JSONL/SOF-ELK formats share `ual_events`. `record_sources` retains each sighting. JSON wins over equivalent CSV, raw over derived, and present per-window/per-page files supersede `Merged/` copies. Hawk 3 Search-AdminAuditLog copies share `admin_audit_events`.
- Hawk state maps into `users`, `role_assignments`, `oauth_grants`, `app_credentials`, `inbox_rules`, `mailboxes`, `audit_config`, `tenant_settings`, `transport_rules`, `remote_domains`, `mobile_devices`, `risky_users`, and `risk_detections`. Newer collections win state conflicts regardless of ingest order. `_Investigate_*` flags link through `collector_flags`. Invictus also supplies `mfa_registration`, `ca_policies`, `applications`, `devices`, `groups`, `group_members`, `security_alerts`, and `secure_score`.
- Event sources map into `signins`, `directory_audits`, `message_trace`, `mailbox_audit_legacy`, `admin_audit_events`, and `azure_activity`. Duplicate events keep the first known value and fill missing fields from later copies. `collection_log` contains Hawk/PSFramework logs. Ambiguous dates in a small file may be resolved from its collection's culture with a warning. XLSX provenance uses sheet rows.
- Invictus MailItemsAccessed Sessions and MessageIDs enrich a loaded UAL record where possible; otherwise Sessions may create partial UAL rows and MessageIDs may create parent-less `mail_items_accessed` rows. `mailbox_permissions`, mailbox audit status, security defaults, organization audit settings, and exported headers populate their respective evidence/state tables. `collector_runs` includes empty runs; empty exports produce warnings. Known unsupported Hawk artifacts are reported `not_supported`, not silently dropped.

Each accepted record carries a source file, line or sheet row, byte range where available, and hash. `sparrow verify TABLE RECORD_KEY --case C [--root MOVED_ROOT]` rechecks that provenance. Ingest reports file errors, record errors, and count reconciliation separately; a partial ingest exits 2, or 6 when the only records not loaded are ones the collector lost.

## Profile and detection data

`ingest` runs `profile` and then detection by default. `--no-detect` on ingest/profile skips only detection. `profile` rebuilds tenant identity from evidence, including UAL organization IDs and sign-in resource tenants. It maintains `tenant_domains`, `licenses`, `user_licenses`, `tenant_capabilities`, `evidence_availability`, `ip_intel`, `identities`/`identity_aliases`, `operation_catalog`, `timeline`, `auth_events`, and `state_absent_in_newer`. Org-level state is merged per tenant in the current-state views. A Hawk licence line is low-confidence because SKU substring matching can overstate P1/P2; Invictus TenantLicenses service plans have higher confidence.

The embedded `data/capabilities.yaml` includes Microsoft Learn sources. `--data DIR`/`SPARROW_DATA` can override embedded data; repeatable `--rules DIR`/`SPARROW_RULES` can add or replace rules and lists. IP enrichment uses bundled Microsoft 365 service ranges and hosting-ASN lists. Optional `--geoip-dir` supplies MaxMind City/ASN; without it, GeoIP-dependent rules are not applicable.

Rules run once per tenant on a locked read-only instance. `detection_runs` records every attempt and reason for `not_applicable` or `error`; one bad rule does not stop the rest. A `requires` capability that is not licensed, `requires_evidence` that is not licensed or not enabled, or missing required GeoIP yields `not_applicable`. Hits merge into `findings` and `finding_evidence`. The fingerprint is SHA-256 over rule ID, tenant key, and `group_by` values separated by 0x1f (default group is `record_key`); the first 16 hex characters are the finding ID. Re-runs add evidence, widen seen times, refresh title/severity, and never delete a finding or overwrite analyst-owned `status`, `disposition_reason`, or `assigned_to`. Rule/list/IOC hash changes set `rule_updated` for re-review. `timeline.finding_count` and `finding_ids` resolve evidence links.

`sparrow rules lint`, `rules test [--rule ID]`, and `rules list [--requires CAP] [--tag TAG]` inspect the pack. Case indicators of type `ip`, `upn`, `app_id`, `domain`, `user_agent`, `rule_name`, `email`, `url`, or `hash` reach `@list:case_iocs.<type>` only when suspicious or malicious. `ioc remove` is soft; `ioc list --include-removed` can still show it.

## Agent decisions, auditing, and output safety

CLI writes are decisions tagged `decided_by = agent:<id>`, optional `on_behalf_of = analyst:<name>`, and `review_state = pending_review`; a new decision returns a reviewed object to pending. Reviews happen outside the CLI through `sparrow_core::case::review::review_accept` / `review_discard` or outside the case entirely. The core review functions take the decision's audit sequence and reject stale review attempts; discarding restores changed fields. Agent notes have no review state, are labeled unreviewed, and are omitted with `export report --reviewed-only`.

The SHA-256 audit chain stores previous-hash and canonical entry JSON. `audit verify` identifies the first bad sequence; `--acknowledge` records an open break so writes can resume. The case's `case_meta` holds the head bookkeeping, so retain the exported head hash outside the case to detect whole-file rollback or coordinated edits. A no-op write adds no audit entry, and detection and exports add none. Pre-audit indicators gain reviewable `legacy_decision` entries during upgrade. `case_meta` also records `post_migration_pending` (a failed derived-table rebuild to retry on the next writable open) and the credential-failure-code list the last profile used.

Plain CLI output escapes control and Unicode format characters from evidence and agent text. Report output escapes Markdown and HTML; the Timeline Explorer CSV uses a UTF-8 BOM and prefixes potentially formula-executing text cells with `'`, leaving timestamp and ID columns untouched. The XLSX workbook writes text as strings, not formulas, with typed numeric/date cells where representable. Export times are UTC. Output files are written through a temporary file and renamed; an `--out` targeting the case, its WAL, or the configured test cache is refused. Notes, narratives, reasons, and comments cap at 16 KiB; titles cap at 500 characters.

Read-only `sparrow query` runs exactly one parsed SELECT on a separate in-memory DuckDB instance with the case attached read-only. External access and extension loading are disabled and settings locked. It can see `case_meta` as well as evidence tables. Use an explicit tenant predicate when tenant scope matters.

## Testing and synthetic data

```bash
cargo build --release                    # first build compiles bundled DuckDB; allow several minutes
cargo test
cargo test -- --ignored
```

`cargo test`, `cargo clippy` and `cargo build` at the root cover the default members (`sparrow-cli`, `sparrow-core`, `sparrow-synth`); the review app (`crates/sparrow-app`) is a workspace member but not a default one, so the default suite needs neither Node nor webview libraries. `--workspace` includes the app. The full gate is `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test`, plus the review app's checks below when the app changed.

The default suite keeps a fast `bec-aitm` representative for every collector in each heavy matrix. Ignored tests carry `#[ignore = "heavy: run with cargo test --workspace -- --ignored"]` and cover every-scenario/collector matrices, volume, and performance checks; run both jobs before merging. Synthetic fixture trees are deterministic and use reserved IP ranges, example domains, and seed-derived IDs. `sparrow synth check` compares an ingested case with `manifest.json`, including positive rules, look-alikes, and benign baseline. `synth coverage` reports rule/storyline gaps; `synth conformance --tree` compares a generated tree with recorded layouts. See the synth README for options and the scenario schema.

Tests share generated trees and copied case files under `target/tmp/sparrow-cache/<build fingerprint>/` (`sparrow_synth::cache`): a tree or case is built once per run, whichever test binary asks first, and each test gets its own case-file copy. The fingerprint covers generator, parsers, profile, schema, rules, scenarios, lockfile, and compiler; a source change selects a new cache and `cargo clean` removes it. `SPARROW_NO_CACHE=1 cargo test` regenerates each tree and case afresh. Both modes must produce the same results.

### Goldens and conformance

Export and availability goldens live under `crates/sparrow-core/tests/golden/`. Re-record only for an intentional behavior change with `SPARROW_RECORD_GOLDEN=1` on the affected test binary, then review each changed golden and explain the reason in the commit message. The export tests redact version and rule-pack hash to avoid unrelated churn. Do not use a blanket re-record to make a failure disappear.

`sparrow synth conformance --tree DIR --collector hawk|invictus|portal` checks generated files against structure-only recorded layouts. `sparrow synth conformance --real DIR --collector hawk|invictus|portal [--seed N]` is an explicitly approved, local, aggregates-only comparison of a capture against generated variants: built-in scenarios, both PowerShell editions, three host cultures, and the collector-specific variant matrix. It reports structure, masked names, formats, and counts, not source values or paths. See the synth README for its limits and privacy contract.

### Build-output housekeeping

`scripts/sweep-target.sh [--days N] [--dry-run] [--force] [TARGET_DIR]` is an opt-in cleanup of stale Cargo output; it never runs automatically. It retains the newest artifact of each crate name/kind in `deps` directories and removes old incremental entries (default age: three days). It skips files modified in the last hour unless `--force` is used. Inspect the `--dry-run` result before using it; needed artifacts can be rebuilt, but the operation deletes files.

## Review app

The analyst's review app is a Tauri v2 desktop app: `crates/sparrow-app` is the backend (each command is a plain function over the app state, wrapped by a thin `#[tauri::command]`; all logic stays in `sparrow-core`), and `app/` is the React + TypeScript (Vite) frontend, which only renders and calls commands through `app/src/api.ts`. Untrusted text is rendered as text through `displaySafe` (`app/src/text.ts`, the same rule as the CLI's `display_safe_line`); ESLint fails on `dangerouslySetInnerHTML`.

Prerequisites: Node 22 and npm, plus the platform's Tauri prerequisites (on macOS, the Xcode Command Line Tools; on Windows, the Visual Studio C++ build tools, a Windows SDK and the WebView2 runtime, with Git Bash for `scripts/release.sh`). Dependencies are pinned by `Cargo.lock` and `app/package-lock.json`; install the frontend's from the lockfile:

```bash
npm --prefix app ci --offline            # or without --offline on a machine with an empty npm cache
npx --prefix app tauri dev               # run from the repo root; starts Vite on :5173 and the app window
```

The Tauri CLI finds `crates/sparrow-app/tauri.conf.json` and runs its `beforeDevCommand` / `beforeBuildCommand` (`npm --prefix ../app run dev` / `npm --prefix ../app run build`). The CLI runs them in `app/` when started from the repo root and in `crates/` when started from `crates/sparrow-app`; `../app` is the front end from both. A plain debug `cargo build -p sparrow-app` loads the frontend from the dev server (`devUrl`); `tauri build` builds the frontend into `app/dist` (git-ignored) and embeds it.

### Release builds

`scripts/release.sh` builds both release binaries from any directory: `--cli` only the CLI (`target/release/sparrow`), `--app` only the review app (`target/release/sparrow-app`, plus a bundle where the script asks Tauri for one, since `tauri.conf.json` leaves bundling off: `target/release/bundle/macos/Sparrow.app` on macOS, and the per-user NSIS installer `target/release/bundle/nsis/Sparrow_<version>_<arch>-setup.exe` on Windows), neither flag both. On Windows, run it from Git Bash; the binaries end in `.exe`, the first bundle downloads the NSIS tools, and the installer holds the app only, not the CLI. It installs the front-end packages from the lockfile first when `app/node_modules` is missing (`NPM_OFFLINE=1` for `npm ci --offline`) and honours `CARGO_TARGET_DIR`.

Windows release builds link the C runtime statically (`+crt-static`, set by the script alone), so they run without the Visual C++ redistributable. To confirm it, `dumpbin /dependents` must not list `MSVCP140.dll` or `VCRUNTIME140.dll`.

### Publishing a release

Cut a release in its own worktree, never by switching branches in a shared checkout: other work may be in progress there, and `scripts/release.sh --package` refuses a tree with changes to `crates/`, `app/` or `Cargo.*` (`RELEASE_ALLOW_DIRTY=1` overrides). `scripts/cut-release.sh` does the mechanical part on macOS and Linux:

1. `scripts/cut-release.sh prepare <version>` creates `../Sparrow-rel-<version>` on branch `release/<version>` off `main`, sets the version in `Cargo.toml` and `app/package.json`, refreshes both lockfiles, and writes `docs/releases/v<version>.md` from the previous release's notes. The tag is `v` plus that exact version.
2. Write "What's new" in those notes (replacing the TODO), and fix the build ordinal in the first line.
3. `scripts/cut-release.sh package <version>` commits the release, packages it into `target/release/dist` (the app and the CLI together, because the two refuse to talk across versions, plus a checksum file), and smoke-tests the uploads: checksums, the CLI's version, a synthetic ingest, and the app starting. Builds are unsigned. On another platform, run `scripts/release.sh --package` from the same commit.
4. Run the publish commands it prints: merge into `main`, tag and push, create the GitHub pre-release from the tag with the notes and every platform's files, and remove the worktree.

A release on a private repository is visible only to people with access to the repository.

### UI debugging in a browser

`npm --prefix app run dev:mock` starts Vite on :5173 in `mock` mode (which sets the compile-time constant `__SPARROW_MOCK__`; no env variable is read, and `npm run dev`, `vite build` in any mode and Vitest compile it to `false`); open <http://localhost:5173> in a normal browser to inspect every screen against a fake backend with no Tauri window and no case. `app/src/mock/backend.ts` answers every command in `app/src/api.ts` with the recorded test fixtures plus generated stress data (a 40-column, 5,000-row table with a 2 KB `raw` cell, long user agents and hostile strings for `browse_page`/`sql_run`, 200-row pivot sections); decisions, timeline edits and highlights live in memory and reset on reload. A SQL text containing `slow` waits 10 s (try Cancel), one containing `error` fails, a case path containing `readonly` opens read-only and one containing `upgrade` asks for the upgrade. A "MOCK BACKEND — synthetic data" badge stays in the corner. The mock is loaded by a dynamic import behind that constant, so a build contains none of it.

Checks when the app changed:

```bash
cargo test -p sparrow-app
cargo clippy -p sparrow-app --all-targets -- -D warnings
npm --prefix app test                    # Vitest
npm --prefix app run lint                # ESLint
npm --prefix app run build               # tsc type check + Vite build
```

Security settings live in `crates/sparrow-app/tauri.conf.json` (CSP: the app's own assets and IPC only) and `crates/sparrow-app/capabilities/default.json` (core defaults plus the open and save dialogs; no shell, fs, http or updater plugins).
