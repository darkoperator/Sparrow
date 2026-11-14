# Sparrow

- **Schema**: `crates/sparrow-core/migrations/` is the source of truth. Grep it for `CREATE TABLE <name>` before naming a new table or column.
- **Tests**: run cargo through `scripts/test-summary.sh <cargo test args>`; it keeps panic messages and logs the full output. One cargo run at a time per checkout: concurrent runs block on the build lock.
- **Golden output**: `crates/sparrow-core/tests/golden/` pins exact coverage, report and export output; a change there is a behaviour change to justify, not a file to regenerate.
- **Synthetic cases**: `crates/sparrow-synth` generates test tenants (`src/testing.rs` is the test harness). Tests use synthetic data only; `hawk test captures/` and `invictus/` are never test inputs.
- **Hooks**: `git config core.hooksPath .githooks` enables the pre-commit fmt/tsc check.
- **Adding a rule**: follow `docs/ADDING-A-RULE.md` (stage values, coverage entry, storyline actors, golden and `detect_stable` re-pinning).
