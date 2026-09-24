# Sparrow

Ingests Microsoft 365 evidence collected with **Hawk** or **Microsoft-Extractor-Suite** into a DuckDB case
database for Business Email Compromise investigations. Every record keeps its source file, line range, byte
range and hash so an analyst can verify it.

## Build

```bash
cargo build --release   # first build compiles DuckDB (several minutes)
```

## Use

```bash
sparrow discover /evidence                        # what was found and how each file is classified
sparrow ingest /evidence --case case.duckdb       # add --culture en-US|en-GB|... if dates are ambiguous
sparrow schema --case case.duckdb                 # tables and column descriptions
sparrow verify collection_log 12:8 --case case.duckdb [--root /moved/evidence]
```

Add `--json` to any command for machine-readable output. `ingest` exits with code 2 when it completed but a file
failed, a record could not be parsed, or a file's record counts did not reconcile; `verify` exits with code 2 when
a record no longer matches its source.
