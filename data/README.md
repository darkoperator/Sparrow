# data/

Embedded data files read by `sparrow_core::data`. Each file is compiled into the `sparrow`
binary with `include_str!` so the tool works with no external files; a directory passed as
`--data DIR` (or the `SPARROW_DATA` environment variable) can supply a file of the same name
that overlays the built-in one: entries are matched by `id` — a matching id replaces the
built-in entry, a new id is added, and any built-in entry with no matching id is kept as is.

## Files

- `capabilities.yaml` — the licensing and retention facts behind the `capabilities` table and,
  later, `evidence_availability`: which Microsoft 365 / Purview / Entra / Defender capability
  requires which Graph `subscribedSkus` service plan, what it costs (retention in days), and
  which evidence tables it unlocks.

Task 7 adds `ms365_ip_ranges.json` (Microsoft's published service-tag IP ranges) here, along
with the recipe for refreshing it.

## Editing rules

Every licensing or retention fact must cite a Microsoft Learn page (or an official Microsoft
blog post) and record the date it was checked in that entry's `as_of` field. Never change a
number without re-checking its cited page; when you do, update `as_of` to the day you checked.
Facts must never be taken from a collector's own built-in rules (Hawk, Microsoft-Extractor-Suite) —
only from Microsoft's own documentation.
