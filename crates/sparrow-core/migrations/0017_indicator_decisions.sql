-- Migration 17: Phase 7 Task 2. Indicators are audited agent decisions with a soft delete (comments only).
COMMENT ON TABLE case_indicators IS 'Indicators (ip, upn, ...) marked by agent decisions. Rules read them through @list:case_iocs.<type>: active rows only (removed_at NULL) with a malicious or suspicious verdict. Written only through sparrow_core::case::indicators, each write tagged (decided_by, decided_at, on_behalf_of, review_state) and audited in audit_trail; removal is a soft delete.';
COMMENT ON COLUMN case_indicators.added_by IS 'Who added it, or last added it again (re-adding updates verdict and note): agent:<id> (Phase 7) or analyst:<name> (earlier cases). decided_by names the last decision of any kind.';
COMMENT ON COLUMN case_indicators.added_at IS 'When it was added or last added again.';
COMMENT ON COLUMN case_indicators.note IS 'Free-text note given with the indicator.';
