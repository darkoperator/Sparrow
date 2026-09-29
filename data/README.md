# data/

Embedded data files read by `sparrow_core::data`. Each file is compiled into the `sparrow`
binary with `include_str!` so the tool works with no external files; a directory passed as
`--data DIR` (or the `SPARROW_DATA` environment variable) can supply a file of the same name
that overlays the built-in one: entries are matched by `id` — a matching id replaces the
built-in entry, a new id is added, and any built-in entry with no matching id is kept as is.

## Files

- `capabilities.yaml` — the licensing and retention facts behind the `capabilities` table and
  `evidence_availability`: which Microsoft 365 / Purview / Entra / Defender capability requires
  which Graph `subscribedSkus` service plan, what it costs (retention in days), and which
  evidence tables it unlocks. The `evidence` ids are the `evidence_availability` source ids
  (`ual`, `signins`, `directory_audits`, `ca_policies`, `risk_detections`, ...); `ca_policies`
  was added in Phase 5 for the Conditional Access policy parser.
- `ms365_ip_ranges.json` — Microsoft's published Microsoft 365 service front-end IP ranges
  (Exchange, SharePoint, Skype, Common), used by `ip_intel.is_microsoft` /
  `microsoft_service_area`. Unlike `capabilities.yaml`, an external `<data>/ms365_ip_ranges.json`
  (`--data DIR`) **replaces** the built-in file wholesale — it is not overlaid entry by entry,
  because the snapshot is all-or-nothing.

## Refreshing ms365_ip_ranges.json

1. Fetch the current version: `https://endpoints.office.com/version/Worldwide?clientrequestid=<new GUID>`.
2. Download the endpoints: `https://endpoints.office.com/endpoints/worldwide?clientrequestid=<GUID>`.
3. Run, with that version and today's date:

   ```bash
   jq '{
     source: "https://endpoints.office.com/endpoints/worldwide",
     documentation: "https://learn.microsoft.com/microsoft-365/enterprise/microsoft-365-ip-web-service",
     instance: "Worldwide",
     version: "<new version>",
     retrieved: "<yyyy-mm-dd>",
     note: "Microsoft 365 service front-end ranges (Exchange, SharePoint, Skype, Common). They identify Microsoft infrastructure, not legitimate clients.",
     ranges: ([.[] | select(.ips) | .serviceArea as $a | .ips[] | {cidr: ., service_area: $a}] | unique_by(.cidr) | sort_by(.cidr))
   }' <downloaded endpoints file> > data/ms365_ip_ranges.json
   ```

4. Commit the refreshed file.

## Editing rules

Every licensing or retention fact must cite a Microsoft Learn page (or an official Microsoft
blog post) and record the date it was checked in that entry's `as_of` field. Never change a
number without re-checking its cited page; when you do, update `as_of` to the day you checked.
Facts must never be taken from a collector's own built-in rules (Hawk, Microsoft-Extractor-Suite) —
only from Microsoft's own documentation.
