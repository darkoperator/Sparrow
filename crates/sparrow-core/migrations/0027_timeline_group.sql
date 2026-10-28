-- Migration 27: grouped timeline entries. An entry may stand for a span of events: end_time closes the span that
-- event_time opens, and event_count says how many events it covers. Both are NULL for an entry about one moment. The
-- evidence rows of a grouped entry stay in timeline_entry_evidence, one per cited event, with no cap.
ALTER TABLE timeline_entries ADD COLUMN end_time TIMESTAMPTZ;
ALTER TABLE timeline_entries ADD COLUMN event_count BIGINT;
COMMENT ON COLUMN timeline_entries.end_time IS 'End of the span a grouped entry covers (UTC); event_time is the start. NULL for an entry about a single moment.';
COMMENT ON COLUMN timeline_entries.event_count IS 'How many events a grouped entry covers, as the analyst grouped them; NULL when not grouped. Not required to equal the number of evidence rows.';
