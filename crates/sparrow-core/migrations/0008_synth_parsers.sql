-- 0008: Phase 5 (synthetic generator and the parsers it drives). Same conventions as
-- 0004-0007: no key constraints; loaders keep keys unique. Each Phase 5 task appends its
-- section below under a "-- Task N:" line.

-- Task 12: record keys restated with their exact hashed text, so the generator's key
-- functions follow the documented contract rather than the parsers' code.
COMMENT ON COLUMN admin_audit_events.record_key IS 'SHA-256 hex (lower-case) of the UTF-8 text "admin_audit\n<run>\n<cmdlet>\n<object>\n<caller>" (lines joined with a single \n, no trailing newline): <run> is the run time in UTC truncated to the second as yyyy-MM-ddTHH:mm:ssZ (RunDate or RunDate(UTC); text that does not parse is used trimmed as written); <cmdlet> is CmdletName (Cmdlet in the summary) lower-cased; <object> is ObjectModified after its last / and then after its last \, lower-cased; <caller> is the caller trimmed of surrounding whitespace (a Sparrow normalization: Hawk''s Get-SimpleAdminAuditLog.ps1 tests the caller untrimmed), then as that Simple_* summary writes it (empty gives ***; a caller containing "on behalf of" gives <first word of its 4th /-segment> on behalf of <its last /-segment>, trailing quotes trimmed), lower-cased. Parameters are not part of the key: Simple_* summaries have none. Zone-less copies (Format-List, full-form CSV) are read as UTC, so they share the key only when the collecting host ran in UTC. A command whose parameters differ from the row already holding the same key gets ''#'' plus the first 12 hex chars of the SHA-256 of its parameters as compact JSON with the names sorted.';
COMMENT ON COLUMN collector_flags.record_key IS 'SHA-256 hex (lower-case) of UTF-8 text joined with a single \n. A record of an _Investigate_* file: "<flag_type>\n<linked_table or empty>\n<basis>", basis being linked_key when it is set, else the record as compact JSON with object keys sorted recursively. An _Investigate.txt entry: "<flag_type>\n<time text or empty>\n<message>". The file splits into entries line by line: a line [<time text>] - [TAG] - <message> or [<time text>] - ## <Tag> ## - <message> (the tag part optional) starts an entry with that time text and message (both trimmed); a line whose trimmed text starts with "Additional Information:" (Hawk 3 writes it indented) is an entry of its own with that trimmed text as message and the time text of the entry above it (none before the first entry); blank lines are skipped; any other line is appended to the message of the entry above as \n plus the trimmed line (or starts an untimed entry when there is none). Byte-identical copies therefore deduplicate.';

-- Task 13: licences.
COMMENT ON TABLE licenses IS 'Tenant licences reported by one collection. High confidence: Microsoft-Extractor-Suite TenantLicenses.csv (Graph subscribedSkus: SKU, capability status, consumed units and service plan names; the collector''s own E3/E5/P1/P2/Retention columns are kept in raw only). Low confidence: the Hawk.log line "M365 License type detected: <tier>", which Hawk derives from SKU-name substrings (E5 is also logged for Office 365 E5, which lacks Entra ID P1/P2; Microsoft 365 E3 is logged Unknown). tenant_capabilities interprets them.';
COMMENT ON COLUMN licenses.service_plans IS 'Service plan names in the SKU, trimmed, blanks dropped (TenantLicenses ServicePlans is the names joined with "; ", without provisioning status).';
COMMENT ON TABLE user_licenses IS 'Licences assigned to users, per collection (Microsoft-Extractor-Suite UserLicenses.csv). Users with no licence (SkuPartNumber None) have no row.';
COMMENT ON COLUMN user_licenses.source IS 'invictus_user_licenses (Microsoft-Extractor-Suite UserLicenses.csv).';
COMMENT ON COLUMN user_licenses.service_plans IS 'Service plan names assigned to the user from this SKU; NULL for UserLicenses.csv, which lists SKUs only.';

-- Task 14: users and role assignments from the Microsoft-Extractor-Suite directory cmdlets.
COMMENT ON TABLE users IS 'Directory users at collection time (Hawk 4 EntraIDUsers, Hawk 3 AzureADUsers, Microsoft-Extractor-Suite Users.csv). One row per record_key; a newer collection replaces the columns it provides (latest wins).';
COMMENT ON COLUMN users.last_signin IS 'Last sign-in time when the source provides it (Microsoft-Extractor-Suite Users.csv: the later of LastSignInDateTime and LastNonInteractiveSignInDateTime; not collected by Hawk).';
COMMENT ON COLUMN users.department IS 'Department when the source provides it (Microsoft-Extractor-Suite Users.csv; not collected by Hawk).';
COMMENT ON COLUMN users.job_title IS 'Job title when the source provides it (Microsoft-Extractor-Suite Users.csv; not collected by Hawk).';
COMMENT ON TABLE role_assignments IS 'Admin role memberships and Exchange role assignments (Entra directory roles via Hawk and the Microsoft-Extractor-Suite Admins/Roles files, Exchange role groups, eDiscovery and ApplicationImpersonation assignments). Latest wins per record_key.';
COMMENT ON COLUMN role_assignments.source IS 'entra_directory (Hawk EntraIDAdministrators/AzureADAdministrators and Microsoft-Extractor-Suite Admins/<role>.csv + Roles/AllRoles.csv), exchange_rbac (ExchangeOnlineAdministrators, Impersonation_Rights), exchange_ediscovery (EDiscoveryRoleAssignments, CustomEDiscoveryRoles), entra_pim (Microsoft-Extractor-Suite Roles/PIM-Assignments.csv).';
COMMENT ON COLUMN role_assignments.assignment_type IS 'active, eligible or permanent (PIM); the Microsoft-Extractor-Suite Admins/AllRoles files are permanent and PIM-Assignments.csv carries PIM Active/PIM Eligible; delegating for Exchange delegating assignments.';
COMMENT ON COLUMN role_assignments.enabled IS 'Exchange role assignment Enabled, or the Microsoft-Extractor-Suite Admins/AllRoles AccountEnabled.';

-- Task 15: MFA registration and Conditional Access policies.
CREATE TABLE mfa_registration (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    upn VARCHAR, user_id VARCHAR, display_name VARCHAR, user_type VARCHAR, is_admin BOOLEAN,
    mfa_status VARCHAR, is_mfa_registered BOOLEAN, is_mfa_capable BOOLEAN,
    is_sspr_registered BOOLEAN, is_sspr_enabled BOOLEAN, is_sspr_capable BOOLEAN,
    is_passwordless_capable BOOLEAN, methods VARCHAR[], default_method VARCHAR,
    system_preferred_methods VARCHAR[], method_email BOOLEAN, method_fido2 BOOLEAN,
    method_authenticator_app BOOLEAN, method_password BOOLEAN, method_phone BOOLEAN,
    method_software_oath BOOLEAN, method_hello_business BOOLEAN,
    method_temporary_access_pass BOOLEAN, method_qr_code_pin BOOLEAN, last_updated TIMESTAMPTZ,
    raw JSON, column_collections JSON, tz_assumed JSON
);
CREATE TABLE ca_policies (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    policy_id VARCHAR, display_name VARCHAR, state VARCHAR, created TIMESTAMPTZ,
    modified TIMESTAMPTZ, description VARCHAR, include_users VARCHAR[], exclude_users VARCHAR[],
    include_groups VARCHAR[], exclude_groups VARCHAR[], include_roles VARCHAR[],
    exclude_roles VARCHAR[], include_applications VARCHAR[], exclude_applications VARCHAR[],
    client_app_types VARCHAR[], include_platforms VARCHAR[], exclude_platforms VARCHAR[],
    include_locations VARCHAR[], exclude_locations VARCHAR[], user_risk_levels VARCHAR[],
    sign_in_risk_levels VARCHAR[], service_principal_risk_levels VARCHAR[],
    user_actions VARCHAR[], built_in_controls VARCHAR[], grant_operator VARCHAR,
    device_filter_mode VARCHAR, device_filter_rule VARCHAR, session_controls JSON,
    raw JSON, column_collections JSON, tz_assumed JSON
);
COMMENT ON TABLE mfa_registration IS 'Authentication methods registered per user (Microsoft-Extractor-Suite Get-MFA: AuthenticationMethods.csv per-method flags, UserRegistrationDetails.csv registration and capability flags). One row per user; each file fills its own columns (latest wins per column).';
COMMENT ON COLUMN mfa_registration.record_key IS 'Lower-case UPN.';
COMMENT ON COLUMN mfa_registration.collection_id IS 'Newest collection that wrote or re-confirmed any of this row''s columns (per-column writers: column_collections).';
COMMENT ON COLUMN mfa_registration.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN mfa_registration.upn IS 'UserPrincipalName, lower-case.';
COMMENT ON COLUMN mfa_registration.user_id IS 'Entra object id (UserRegistrationDetails id).';
COMMENT ON COLUMN mfa_registration.display_name IS 'userDisplayName.';
COMMENT ON COLUMN mfa_registration.user_type IS 'userType: member or guest.';
COMMENT ON COLUMN mfa_registration.is_admin IS 'isAdmin: the user holds an admin directory role.';
COMMENT ON COLUMN mfa_registration.mfa_status IS 'AuthenticationMethods MFAstatus: Enabled when any method other than password / qrCodePin exists, else Disabled.';
COMMENT ON COLUMN mfa_registration.is_mfa_registered IS 'isMfaRegistered.';
COMMENT ON COLUMN mfa_registration.is_mfa_capable IS 'isMfaCapable.';
COMMENT ON COLUMN mfa_registration.is_sspr_registered IS 'isSsprRegistered.';
COMMENT ON COLUMN mfa_registration.is_sspr_enabled IS 'isSsprEnabled.';
COMMENT ON COLUMN mfa_registration.is_sspr_capable IS 'isSsprCapable.';
COMMENT ON COLUMN mfa_registration.is_passwordless_capable IS 'isPasswordlessCapable.';
COMMENT ON COLUMN mfa_registration.methods IS 'methodsRegistered (Graph names, e.g. microsoftAuthenticatorPush), split on ", ".';
COMMENT ON COLUMN mfa_registration.default_method IS 'userPreferredMethodForSecondaryAuthentication (push, ...).';
COMMENT ON COLUMN mfa_registration.system_preferred_methods IS 'systemPreferredAuthenticationMethods, split on ", ".';
COMMENT ON COLUMN mfa_registration.method_email IS 'AuthenticationMethods email: an email authentication method is registered.';
COMMENT ON COLUMN mfa_registration.method_fido2 IS 'AuthenticationMethods fido2: a FIDO2 security key is registered.';
COMMENT ON COLUMN mfa_registration.method_authenticator_app IS 'AuthenticationMethods app: the Microsoft Authenticator app is registered.';
COMMENT ON COLUMN mfa_registration.method_password IS 'AuthenticationMethods password: a password method exists (every user).';
COMMENT ON COLUMN mfa_registration.method_phone IS 'AuthenticationMethods phone: a phone method is registered.';
COMMENT ON COLUMN mfa_registration.method_software_oath IS 'AuthenticationMethods softwareoath: a software OATH token is registered.';
COMMENT ON COLUMN mfa_registration.method_hello_business IS 'AuthenticationMethods hellobusiness: Windows Hello for Business is registered.';
COMMENT ON COLUMN mfa_registration.method_temporary_access_pass IS 'AuthenticationMethods temporaryAccessPass: a temporary access pass is registered.';
COMMENT ON COLUMN mfa_registration.method_qr_code_pin IS 'AuthenticationMethods qrcodepin: a QR-code PIN is registered.';
COMMENT ON COLUMN mfa_registration.last_updated IS 'lastUpdatedDateTime.';
COMMENT ON COLUMN mfa_registration.raw IS 'Source record as loaded; records from the two files are merged (json_merge_patch).';
COMMENT ON COLUMN mfa_registration.column_collections IS 'Object {column: collection_id} naming the collection that last wrote each column. Per-column latest wins: a load writes a column only when its collection is not older than the one recorded for it, so column values do not depend on ingest order. Columns no load has written (or loaded only as NULL where NULL keeps the stored value) are absent.';
COMMENT ON COLUMN mfa_registration.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON TABLE ca_policies IS 'Entra Conditional Access policies at collection time (Microsoft-Extractor-Suite Get-ConditionalAccessPolicies).';
COMMENT ON COLUMN ca_policies.record_key IS 'Lower-case policy id.';
COMMENT ON COLUMN ca_policies.collection_id IS 'Newest collection that wrote or re-confirmed any of this row''s columns (per-column writers: column_collections).';
COMMENT ON COLUMN ca_policies.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN ca_policies.policy_id IS 'Policy Id (GUID).';
COMMENT ON COLUMN ca_policies.display_name IS 'DisplayName.';
COMMENT ON COLUMN ca_policies.state IS 'State: enabled, disabled or enabledForReportingButNotEnforced.';
COMMENT ON COLUMN ca_policies.created IS 'CreatedDateTime.';
COMMENT ON COLUMN ca_policies.modified IS 'ModifiedDateTime (NULL when never modified).';
COMMENT ON COLUMN ca_policies.description IS 'Description.';
COMMENT ON COLUMN ca_policies.include_users IS 'Conditions.Users.IncludeUsers, "; "-joined (GUIDs or All/None/GuestsOrExternalUsers).';
COMMENT ON COLUMN ca_policies.exclude_users IS 'Conditions.Users.ExcludeUsers, "; "-joined.';
COMMENT ON COLUMN ca_policies.include_groups IS 'Conditions.Users.IncludeGroups, "; "-joined.';
COMMENT ON COLUMN ca_policies.exclude_groups IS 'Conditions.Users.ExcludeGroups, "; "-joined.';
COMMENT ON COLUMN ca_policies.include_roles IS 'Conditions.Users.IncludeRoles, "; "-joined.';
COMMENT ON COLUMN ca_policies.exclude_roles IS 'Conditions.Users.ExcludeRoles, "; "-joined.';
COMMENT ON COLUMN ca_policies.include_applications IS 'Conditions.Applications.IncludeApplications, "; "-joined.';
COMMENT ON COLUMN ca_policies.exclude_applications IS 'Conditions.Applications.ExcludeApplications, "; "-joined.';
COMMENT ON COLUMN ca_policies.client_app_types IS 'Conditions.ClientAppTypes, "; "-joined.';
COMMENT ON COLUMN ca_policies.include_platforms IS 'Conditions.Platforms.IncludePlatforms, "; "-joined.';
COMMENT ON COLUMN ca_policies.exclude_platforms IS 'Conditions.Platforms.ExcludePlatforms, "; "-joined.';
COMMENT ON COLUMN ca_policies.include_locations IS 'Conditions.Locations.IncludeLocations, "; "-joined.';
COMMENT ON COLUMN ca_policies.exclude_locations IS 'Conditions.Locations.ExcludeLocations, "; "-joined.';
COMMENT ON COLUMN ca_policies.user_risk_levels IS 'Conditions.UserRiskLevels, "; "-joined.';
COMMENT ON COLUMN ca_policies.sign_in_risk_levels IS 'Conditions.SignInRiskLevels, "; "-joined.';
COMMENT ON COLUMN ca_policies.service_principal_risk_levels IS 'Conditions.ServicePrincipalRiskLevels, "; "-joined.';
COMMENT ON COLUMN ca_policies.user_actions IS 'Conditions.Applications.IncludeUserActions, "; "-joined.';
COMMENT ON COLUMN ca_policies.built_in_controls IS 'GrantControls.BuiltInControls, "; "-joined (mfa, compliantDevice, block, ...).';
COMMENT ON COLUMN ca_policies.grant_operator IS 'GrantControls.Operator (OR/AND).';
COMMENT ON COLUMN ca_policies.device_filter_mode IS 'Conditions.Devices.DeviceFilter.Mode.';
COMMENT ON COLUMN ca_policies.device_filter_rule IS 'Conditions.Devices.DeviceFilter.Rule.';
COMMENT ON COLUMN ca_policies.session_controls IS 'Object with the session settings the collector exports: application_enforced_restrictions, cloud_app_security, disable_resilience_defaults, persistent_browser, sign_in_frequency (absent keys = not configured).';
COMMENT ON COLUMN ca_policies.raw IS 'Source record as loaded.';
COMMENT ON COLUMN ca_policies.column_collections IS 'Object {column: collection_id} naming the collection that last wrote each column. Per-column latest wins: a load writes a column only when its collection is not older than the one recorded for it, so column values do not depend on ingest order. Columns no load has written (or loaded only as NULL where NULL keeps the stored value) are absent.';
COMMENT ON COLUMN ca_policies.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';

-- Task 16: applications and service principals.
CREATE TABLE applications (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    app_id VARCHAR, object_id VARCHAR, display_name VARCHAR, description VARCHAR,
    owner_org_id VARCHAR, created TIMESTAMPTZ, enabled BOOLEAN, publisher VARCHAR,
    verified_publisher VARCHAR, sign_in_audience VARCHAR, application_type VARCHAR,
    reply_urls VARCHAR[], has_secrets BOOLEAN, has_certs BOOLEAN,
    required_api_permission_count INTEGER, association_type VARCHAR, associated_user VARCHAR,
    raw JSON, column_collections JSON, tz_assumed JSON
);
COMMENT ON TABLE applications IS 'Applications, service principals and per-user app associations (Microsoft-Extractor-Suite EntraID ServicePrincipals/AppRegistrations and the triage UserApplications.csv; Hawk credential files do not create rows). Latest wins per record_key.';
COMMENT ON COLUMN applications.record_key IS 'Lower-case app id (ServicePrincipals, AppRegistrations); UserApplications rows add |<lower AssociationType>|<lower AssociatedUser> so each user–app association is its own row.';
COMMENT ON COLUMN applications.collection_id IS 'Newest collection that wrote or re-confirmed any of this row''s columns (per-column writers: column_collections).';
COMMENT ON COLUMN applications.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN applications.app_id IS 'Application (AppId), lower-case.';
COMMENT ON COLUMN applications.object_id IS 'Application (AppRegistrations Id) or service principal (UserApplications ObjectId) object id, lower-case.';
COMMENT ON COLUMN applications.display_name IS 'AppDisplayName / DisplayName / UserApplications ApplicationName.';
COMMENT ON COLUMN applications.description IS 'AppDescription (ServicePrincipals).';
COMMENT ON COLUMN applications.owner_org_id IS 'AppOwnerOrganizationId (the tenant that owns the app).';
COMMENT ON COLUMN applications.created IS 'Application CreatedDateTime.';
COMMENT ON COLUMN applications.enabled IS 'AccountEnabled / UserApplications ServicePrincipalEnabled (NULL when the collector wrote N/A).';
COMMENT ON COLUMN applications.publisher IS 'PublisherName.';
COMMENT ON COLUMN applications.verified_publisher IS 'Verified publisher display name (ServicePrincipals.csv carries none).';
COMMENT ON COLUMN applications.sign_in_audience IS 'SignInAudience.';
COMMENT ON COLUMN applications.application_type IS 'UserApplications ApplicationType: Microsoft Application, Managed Identity, Enterprise Application or Internal Application.';
COMMENT ON COLUMN applications.reply_urls IS 'Redirect URIs (UserApplications WebRedirectUris + PublicClientRedirectUris), "; "-joined.';
COMMENT ON COLUMN applications.has_secrets IS 'The app registration has password credentials (UserApplications HasClientSecrets; NULL when the collector wrote N/A).';
COMMENT ON COLUMN applications.has_certs IS 'The app registration has key credentials (UserApplications HasCertificates; NULL when the collector wrote N/A).';
COMMENT ON COLUMN applications.required_api_permission_count IS 'UserApplications RequiredApiPermissionCount (NULL when the collector wrote N/A).';
COMMENT ON COLUMN applications.association_type IS 'UserApplications AssociationType: Owner or Assignment (NULL for the ServicePrincipals / AppRegistrations rows).';
COMMENT ON COLUMN applications.associated_user IS 'UserApplications AssociatedUser UPN, lower-case.';
COMMENT ON COLUMN applications.raw IS 'Source record as loaded; records from several files are merged (json_merge_patch).';
COMMENT ON COLUMN applications.column_collections IS 'Object {column: collection_id} naming the collection that last wrote each column. Per-column latest wins: a load writes a column only when its collection is not older than the one recorded for it, so column values do not depend on ingest order. Columns no load has written (or loaded only as NULL where NULL keeps the stored value) are absent.';
COMMENT ON COLUMN applications.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
