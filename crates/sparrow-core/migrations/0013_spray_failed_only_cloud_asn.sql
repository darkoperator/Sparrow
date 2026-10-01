-- Migration 13: spray source = failed-only users; cloud service per (application, ASN) (Phase 6 tuning r6).

ALTER TABLE spray_sources ADD COLUMN failed_only_users BIGINT;
ALTER TABLE spray_sources ADD COLUMN success_users BIGINT;

COMMENT ON TABLE spray_sources IS 'Password-spray source addresses per tenant, rewritten by every profile run: an address from which at least 5 distinct users of the tenant had an INTERACTIVE credential failure (the credential_failure_codes list: 50126, 50053, ...) and NEVER a known success (error_code 0) from that address in the case ("failed-only" users), and those failed-only users outnumber the distinct users that did sign in successfully from the address (an office NAT or VPN egress, where users mistype or have stale devices but many more succeed, is not a source). A proxy that sprays many accounts and takes over a few stays a source. The address type does not matter and no GeoIP is needed. Rules read it through the tenant scope like any tenant-aware table.';
COMMENT ON COLUMN spray_sources.users_targeted IS 'Distinct users (lower-cased UPN) with an interactive credential failure from this address (including users that also succeeded from it).';
COMMENT ON COLUMN spray_sources.failures IS 'Interactive credential failures from this address.';
COMMENT ON COLUMN spray_sources.first_failure IS 'Time of the first credential failure from this address.';
COMMENT ON COLUMN spray_sources.last_failure IS 'Time of the last credential failure from this address.';
COMMENT ON COLUMN spray_sources.failed_only_users IS 'Distinct users with a credential failure from this address and no known success from it anywhere in the case.';
COMMENT ON COLUMN spray_sources.success_users IS 'Distinct users with a known success (error_code 0) from this address.';

ALTER TABLE cloud_services ADD COLUMN asn INTEGER;

COMMENT ON TABLE cloud_services IS 'Tenant-wide cloud services per tenant, rewritten by every profile run, one row per (application, hosting ASN): at least 5 distinct users have known successes (error_code 0, interactive or not) to the application from that hosting ASN (ip_intel.is_hosting) on at least 3 distinct UTC days AND those sign-ins are at least 80% of the application''s known successes, established from a prefix of the history (established_day). Typical case: a third-party SaaS connector whose public-cloud backend signs users in on their behalf (the portal export records those as interactive). A rule excuses only sign-ins to that application from that same ASN on a later day. No application name or id is involved.';
COMMENT ON COLUMN cloud_services.asn IS 'The hosting ASN (ip_intel.asn) the service signs in from.';
COMMENT ON COLUMN cloud_services.hosting_users IS 'Distinct users (lower-cased UPN) with a known success to the application from this ASN up to established_day.';
COMMENT ON COLUMN cloud_services.hosting_days IS 'Distinct UTC days with a known success to the application from this ASN up to established_day.';
COMMENT ON COLUMN cloud_services.signins IS 'Known successful sign-ins to the application (any address) up to established_day.';
COMMENT ON COLUMN cloud_services.hosting_signins IS 'Known successful sign-ins to the application from this ASN up to established_day.';
COMMENT ON COLUMN cloud_services.established_day IS 'The UTC day number (epoch days) at the end of which the application first met the profile for this ASN, counting interactive and non-interactive known successes up to that day. A rule excuses only sign-ins of a later day; the establishing days themselves are not excused.';
