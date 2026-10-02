-- Migration 14: cloud_services is established from the whole case, no prefix (Phase 6 tuning r7).
-- A capture is a window: a connector in use since before it starts would only be "established" a few
-- days before the window ends, so a prefix leaves every earlier day counting.

ALTER TABLE cloud_services DROP COLUMN established_day;

COMMENT ON TABLE cloud_services IS 'Tenant-wide cloud services per tenant, rewritten by every profile run, one row per (application, hosting ASN), established from the WHOLE case: at least 5 distinct users have known successes (error_code 0, interactive or not) to the application from that hosting ASN (ip_intel.is_hosting) on at least 3 distinct UTC days AND those sign-ins are at least 80% of the application''s known successes. Typical case: a third-party SaaS connector whose public-cloud backend signs users in on their behalf (the portal export records those as interactive). A rule excuses every sign-in to that application from that same ASN; a spray-source sign-in and a UAL UserLoggedIn always count. No application name or id is involved.';
COMMENT ON COLUMN cloud_services.hosting_users IS 'Distinct users (lower-cased UPN) with a known success to the application from this ASN in the case.';
COMMENT ON COLUMN cloud_services.hosting_days IS 'Distinct UTC days with a known success to the application from this ASN in the case.';
COMMENT ON COLUMN cloud_services.signins IS 'Known successful sign-ins to the application (any address) in the case.';
COMMENT ON COLUMN cloud_services.hosting_signins IS 'Known successful sign-ins to the application from this ASN in the case.';
