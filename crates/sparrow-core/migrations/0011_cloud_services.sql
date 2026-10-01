-- Migration 11: cloud_services (Phase 6 tuning). The per-tenant tenant-wide cloud service relation,
-- derived by the profile step so SPW-ID-002 and SPW-ID-003 share one definition.

CREATE TABLE cloud_services (
    tenant_key VARCHAR NOT NULL,
    app_id VARCHAR NOT NULL,
    hosting_users BIGINT NOT NULL,
    hosting_days BIGINT NOT NULL,
    signins BIGINT NOT NULL,
    hosting_signins BIGINT NOT NULL
);

COMMENT ON TABLE cloud_services IS 'Tenant-wide cloud services per tenant, rewritten by every profile run: an application whose successful sign-ins in this tenant come from hosting ASNs (ip_intel.is_hosting) for at least 5 distinct users on at least 3 distinct UTC days AND at least 80% of its successful sign-ins are from hosting ASNs. Typical case: a third-party SaaS connector whose public-cloud backend signs users in on their behalf. Only sign-ins with a KNOWN success (error_code 0) count. No application name or id is involved. Rules read it through the tenant scope like any tenant-aware table.';
COMMENT ON COLUMN cloud_services.tenant_key IS 'The tenant (tenant.tenant_key). The rule scope shows a rule only its own tenant''s rows.';
COMMENT ON COLUMN cloud_services.app_id IS 'The application id, lower-case, as signins.app_id stores it.';
COMMENT ON COLUMN cloud_services.hosting_users IS 'Distinct users (lower-cased UPN) with a successful sign-in to the application from a hosting ASN.';
COMMENT ON COLUMN cloud_services.hosting_days IS 'Distinct UTC days with a successful sign-in to the application from a hosting ASN.';
COMMENT ON COLUMN cloud_services.signins IS 'Successful sign-ins to the application.';
COMMENT ON COLUMN cloud_services.hosting_signins IS 'Successful sign-ins to the application from a hosting ASN.';
