-- Migration 10: spray_sources (Phase 6 tuning). The per-tenant password-spray source relation, derived
-- by the profile step so every rule uses one definition.

CREATE TABLE spray_sources (
    tenant_key VARCHAR NOT NULL,
    ip VARCHAR NOT NULL,
    users_targeted BIGINT NOT NULL,
    failures BIGINT NOT NULL,
    first_failure TIMESTAMPTZ NOT NULL,
    last_failure TIMESTAMPTZ NOT NULL
);

COMMENT ON TABLE spray_sources IS 'Password-spray source addresses per tenant, rewritten by every profile run: an address with failed sign-ins (signins.error_code non-zero, excluding the interrupt codes a normal MFA or password prompt produces) against at least 5 distinct users of the tenant in the case, that is not regular tenant egress (an address from which at least 5 distinct users signed in successfully on at least 3 distinct UTC days). The address type does not matter: compromised ISP routers and residential proxies count as much as hosting providers. No GeoIP is needed. Rules read it through the tenant scope like any tenant-aware table.';
COMMENT ON COLUMN spray_sources.tenant_key IS 'The tenant the source sprayed (tenant.tenant_key). The rule scope shows a rule only its own tenant''s rows.';
COMMENT ON COLUMN spray_sources.ip IS 'The source address, text exactly as signins.ip stores it.';
COMMENT ON COLUMN spray_sources.users_targeted IS 'Distinct users (lower-cased UPN) with a failed sign-in from this address.';
COMMENT ON COLUMN spray_sources.failures IS 'Failed sign-ins from this address (interrupt codes excluded).';
COMMENT ON COLUMN spray_sources.first_failure IS 'Time of the first failed sign-in from this address.';
COMMENT ON COLUMN spray_sources.last_failure IS 'Time of the last failed sign-in from this address.';
