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

-- Task 17: devices and groups.
CREATE TABLE devices (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    device_id VARCHAR, object_id VARCHAR, display_name VARCHAR, os VARCHAR, os_version VARCHAR,
    trust_type VARCHAR, is_compliant BOOLEAN, is_managed BOOLEAN, is_rooted BOOLEAN,
    enabled BOOLEAN, ownership VARCHAR, enrollment_type VARCHAR, management_type VARCHAR,
    manufacturer VARCHAR, model VARCHAR, profile_type VARCHAR, on_prem_sync BOOLEAN,
    created TIMESTAMPTZ, last_signin TIMESTAMPTZ, owners VARCHAR[], users VARCHAR[],
    raw JSON, column_collections JSON, tz_assumed JSON
);
CREATE TABLE groups (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    group_id VARCHAR, display_name VARCHAR, description VARCHAR, mail VARCHAR,
    mail_enabled BOOLEAN, mail_nickname VARCHAR, security_enabled BOOLEAN, group_types VARCHAR[],
    is_dynamic BOOLEAN, membership_rule VARCHAR, membership_rule_state VARCHAR,
    created TIMESTAMPTZ, renewed TIMESTAMPTZ, expiration TIMESTAMPTZ, visibility VARCHAR,
    on_prem_sync BOOLEAN, is_assignable_to_role BOOLEAN, classification VARCHAR,
    proxy_addresses VARCHAR[], raw JSON, column_collections JSON, tz_assumed JSON
);
CREATE TABLE group_members (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    group_id VARCHAR, group_name VARCHAR, member_id VARCHAR, member_display_name VARCHAR,
    member_mail VARCHAR, member_upn VARCHAR, raw JSON, column_collections JSON, tz_assumed JSON
);
COMMENT ON TABLE devices IS 'Entra devices at collection time (Microsoft-Extractor-Suite Get-Devices Devices.csv, or the same objects as JSON in the .csv path).';
COMMENT ON COLUMN devices.record_key IS 'Lower-case DeviceId.';
COMMENT ON COLUMN devices.collection_id IS 'Newest collection that wrote or re-confirmed any of this row''s columns (per-column writers: column_collections).';
COMMENT ON COLUMN devices.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN devices.device_id IS 'DeviceId (the device''s Entra device id).';
COMMENT ON COLUMN devices.object_id IS 'ObjectId (the directory object id), lower-case.';
COMMENT ON COLUMN devices.display_name IS 'DisplayName.';
COMMENT ON COLUMN devices.os IS 'OperatingSystem.';
COMMENT ON COLUMN devices.os_version IS 'OperatingSystemVersion.';
COMMENT ON COLUMN devices.trust_type IS 'TrustType (AzureAd, Workplace, ServerAd).';
COMMENT ON COLUMN devices.is_compliant IS 'IsCompliant (NULL when the collector wrote nothing).';
COMMENT ON COLUMN devices.is_managed IS 'IsManaged.';
COMMENT ON COLUMN devices.is_rooted IS 'IsRooted.';
COMMENT ON COLUMN devices.enabled IS 'AccountEnabled.';
COMMENT ON COLUMN devices.ownership IS 'DeviceOwnership.';
COMMENT ON COLUMN devices.enrollment_type IS 'EnrollmentType.';
COMMENT ON COLUMN devices.management_type IS 'ManagementType.';
COMMENT ON COLUMN devices.manufacturer IS 'Manufacturer.';
COMMENT ON COLUMN devices.model IS 'Model.';
COMMENT ON COLUMN devices.profile_type IS 'ProfileType.';
COMMENT ON COLUMN devices.on_prem_sync IS 'OnPremisesSyncEnabled.';
COMMENT ON COLUMN devices.created IS 'Registration time when the collector exported it; Microsoft-Extractor-Suite 4.1.0 reads a property v1.0 does not return, so it is usually NULL.';
COMMENT ON COLUMN devices.last_signin IS 'ApproximateLastSignInDateTime as the collector formats it (yyyy-MM-dd HH:mm:ss, UTC by inference; see tz_assumed).';
COMMENT ON COLUMN devices.owners IS 'RegisteredOwners (empty without -UserIds).';
COMMENT ON COLUMN devices.users IS 'RegisteredUsers (empty without -UserIds).';
COMMENT ON COLUMN devices.raw IS 'Source record as loaded.';
COMMENT ON COLUMN devices.column_collections IS 'Object {column: collection_id} naming the collection that last wrote each column. Per-column latest wins: a load writes a column only when its collection is not older than the one recorded for it, so column values do not depend on ingest order. Columns no load has written (or loaded only as NULL where NULL keeps the stored value) are absent.';
COMMENT ON COLUMN devices.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON TABLE groups IS 'Entra groups at collection time (Microsoft-Extractor-Suite Get-Groups Groups.csv and Get-DynamicGroups DynamicGroups.csv; the dynamic file fills the same rows).';
COMMENT ON COLUMN groups.record_key IS 'Lower-case GroupId.';
COMMENT ON COLUMN groups.collection_id IS 'Newest collection that wrote or re-confirmed any of this row''s columns (per-column writers: column_collections).';
COMMENT ON COLUMN groups.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN groups.group_id IS 'GroupId (the group object id), lower-case.';
COMMENT ON COLUMN groups.display_name IS 'DisplayName.';
COMMENT ON COLUMN groups.description IS 'Description.';
COMMENT ON COLUMN groups.mail IS 'Mail address of a mail-enabled group.';
COMMENT ON COLUMN groups.mail_enabled IS 'MailEnabled.';
COMMENT ON COLUMN groups.mail_nickname IS 'MailNickname.';
COMMENT ON COLUMN groups.security_enabled IS 'SecurityEnabled.';
COMMENT ON COLUMN groups.group_types IS 'GroupTypes, joined with "," (no space).';
COMMENT ON COLUMN groups.is_dynamic IS 'GroupTypes contains DynamicMembership or a membership rule is set.';
COMMENT ON COLUMN groups.membership_rule IS 'MembershipRule.';
COMMENT ON COLUMN groups.membership_rule_state IS 'MembershipRuleProcessingState (On, Paused).';
COMMENT ON COLUMN groups.created IS 'CreatedDateTime.';
COMMENT ON COLUMN groups.renewed IS 'RenewedDateTime.';
COMMENT ON COLUMN groups.expiration IS 'ExpirationDateTime.';
COMMENT ON COLUMN groups.visibility IS 'Visibility (Public, Private, HiddenMembership).';
COMMENT ON COLUMN groups.on_prem_sync IS 'OnPremisesSyncEnabled.';
COMMENT ON COLUMN groups.is_assignable_to_role IS 'IsAssignableToRole.';
COMMENT ON COLUMN groups.classification IS 'Classification.';
COMMENT ON COLUMN groups.proxy_addresses IS 'ProxyAddresses, joined with ";" (no space).';
COMMENT ON COLUMN groups.raw IS 'Source record as loaded; records from several files are merged (json_merge_patch).';
COMMENT ON COLUMN groups.column_collections IS 'Object {column: collection_id} naming the collection that last wrote each column. Per-column latest wins: a load writes a column only when its collection is not older than the one recorded for it, so column values do not depend on ingest order. Columns no load has written (or loaded only as NULL where NULL keeps the stored value) are absent.';
COMMENT ON COLUMN groups.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON TABLE group_members IS 'Direct members of Entra groups (Microsoft-Extractor-Suite Get-GroupMembers GroupMembers.csv).';
COMMENT ON COLUMN group_members.record_key IS '<lower group id>|<lower member id>.';
COMMENT ON COLUMN group_members.collection_id IS 'Newest collection that wrote or re-confirmed any of this row''s columns (per-column writers: column_collections).';
COMMENT ON COLUMN group_members.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN group_members.group_id IS 'GroupId (the group object id), lower-case.';
COMMENT ON COLUMN group_members.group_name IS 'GroupName.';
COMMENT ON COLUMN group_members.member_id IS 'MemberId (the member object id), lower-case.';
COMMENT ON COLUMN group_members.member_display_name IS 'DisplayName of the member (NULL for member types without one).';
COMMENT ON COLUMN group_members.member_mail IS 'Email of the member (NULL for member types without one).';
COMMENT ON COLUMN group_members.member_upn IS 'UserPrincipalName of a user member, lower-case (NULL otherwise).';
COMMENT ON COLUMN group_members.raw IS 'Source record as loaded.';
COMMENT ON COLUMN group_members.column_collections IS 'Object {column: collection_id} naming the collection that last wrote each column. Per-column latest wins: a load writes a column only when its collection is not older than the one recorded for it, so column values do not depend on ingest order. Columns no load has written (or loaded only as NULL where NULL keeps the stored value) are absent.';
COMMENT ON COLUMN group_members.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';

-- Task 18: risky users, risk detections, security alerts and secure score.
CREATE TABLE security_alerts (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    alert_id VARCHAR, created_time TIMESTAMPTZ, event_time TIMESTAMPTZ,
    last_modified TIMESTAMPTZ, closed_time TIMESTAMPTZ, title VARCHAR, category VARCHAR,
    severity VARCHAR, status VARCHAR, description VARCHAR, detection_source VARCHAR,
    affected_users VARCHAR[], affected_ips VARCHAR[], affected_hosts VARCHAR[],
    azure_tenant_id VARCHAR, confidence INTEGER, provider VARCHAR, vendor VARCHAR,
    incident_ids VARCHAR[], comments VARCHAR, tags VARCHAR[], raw JSON, column_collections JSON,
    tz_assumed JSON
);
CREATE TABLE secure_score (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    title VARCHAR, category VARCHAR, service VARCHAR, status VARCHAR, current_score DOUBLE,
    max_score DOUBLE, state VARCHAR, action_type VARCHAR, action_url VARCHAR,
    implementation_cost VARCHAR, user_impact VARCHAR, tier VARCHAR, rank INTEGER,
    deprecated BOOLEAN, threats VARCHAR[], last_modified TIMESTAMPTZ, raw JSON,
    column_collections JSON, tz_assumed JSON
);
COMMENT ON TABLE security_alerts IS 'Microsoft Defender security alerts (Microsoft-Extractor-Suite Get-SecurityAlerts SecurityAlerts.csv, legacy Get-MgSecurityAlert rendering). An event table (fill missing): the first copy of an alert wins and later copies only fill values still NULL.';
COMMENT ON COLUMN security_alerts.record_key IS 'Lower-case alert Id.';
COMMENT ON COLUMN security_alerts.collection_id IS 'Collection that first delivered the row (fill missing: later copies never overwrite).';
COMMENT ON COLUMN security_alerts.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN security_alerts.alert_id IS 'Id (Graph alert id), lower-case.';
COMMENT ON COLUMN security_alerts.created_time IS 'CreatedDateTime.';
COMMENT ON COLUMN security_alerts.event_time IS 'EventDateTime (v1 legacy alerts; NULL for the v2 model).';
COMMENT ON COLUMN security_alerts.last_modified IS 'LastModifiedDateTime (v1 legacy alerts; NULL for the v2 model).';
COMMENT ON COLUMN security_alerts.closed_time IS 'ClosedDateTime (v1 legacy alerts; NULL for the v2 model).';
COMMENT ON COLUMN security_alerts.title IS 'Title.';
COMMENT ON COLUMN security_alerts.category IS 'Category.';
COMMENT ON COLUMN security_alerts.severity IS 'Severity: high, medium, low, informational or unknown.';
COMMENT ON COLUMN security_alerts.status IS 'Status: newAlert, inProgress, resolved or unknown (new, inProgress, resolved on v2).';
COMMENT ON COLUMN security_alerts.description IS 'Description.';
COMMENT ON COLUMN security_alerts.detection_source IS 'DetectionSource.';
COMMENT ON COLUMN security_alerts.affected_users IS 'UPN parts of the AffectedUser entries ("<upn>/<ip>" joined with "; "), NULL when empty.';
COMMENT ON COLUMN security_alerts.affected_ips IS 'IP parts of the AffectedUser entries, the literal null dropped, NULL when empty.';
COMMENT ON COLUMN security_alerts.affected_hosts IS 'Host parts of the AffectedHost entries ("<host>/<ip>" joined with "; "), NULL when empty.';
COMMENT ON COLUMN security_alerts.azure_tenant_id IS 'AzureTenantId (v1 legacy alerts; NULL for the v2 model, which uses tenantId).';
COMMENT ON COLUMN security_alerts.confidence IS 'Confidence (v1 legacy alerts; NULL for the v2 model).';
COMMENT ON COLUMN security_alerts.provider IS 'Provider from VendorInformation (v1 legacy alerts).';
COMMENT ON COLUMN security_alerts.vendor IS 'Vendor from VendorInformation (v1 legacy alerts).';
COMMENT ON COLUMN security_alerts.incident_ids IS 'IncidentIds joined with ", ", NULL when empty.';
COMMENT ON COLUMN security_alerts.comments IS 'Comments joined with "; " (legacy comments are plain strings, so each item is its text).';
COMMENT ON COLUMN security_alerts.tags IS 'Tags joined with ", ", NULL when empty.';
COMMENT ON COLUMN security_alerts.raw IS 'Source record as loaded.';
COMMENT ON COLUMN security_alerts.column_collections IS 'Object {column: collection_id} naming the collection that last wrote each column. Per-column latest wins: a load writes a column only when its collection is not older than the one recorded for it, so column values do not depend on ingest order. Columns no load has written (or loaded only as NULL where NULL keeps the stored value) are absent.';
COMMENT ON COLUMN security_alerts.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';
COMMENT ON TABLE secure_score IS 'Microsoft Secure Score control profiles (Microsoft-Extractor-Suite Get-SecureScore SecureScore.csv, one row per control profile joined to its score).';
COMMENT ON COLUMN secure_score.record_key IS '<collection_id>|<lower Title> (the export carries no control id, so the collection-scoped title keys the row).';
COMMENT ON COLUMN secure_score.collection_id IS 'Newest collection that wrote or re-confirmed any of this row''s columns (per-column writers: column_collections).';
COMMENT ON COLUMN secure_score.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN secure_score.title IS 'Title.';
COMMENT ON COLUMN secure_score.category IS 'ControlCategory.';
COMMENT ON COLUMN secure_score.service IS 'Service.';
COMMENT ON COLUMN secure_score.status IS 'Status derived by the collector: Not applicable, Not applicable (overridden: <state>), Meets standard, Partial or At risk.';
COMMENT ON COLUMN secure_score.current_score IS 'CurrentScore; the collector''s culture-formatted double, parsed strictly ("2,5" -> 2.5).';
COMMENT ON COLUMN secure_score.max_score IS 'MaxScore; a culture-formatted double like current_score.';
COMMENT ON COLUMN secure_score.state IS 'The last ControlStateUpdates State, else Default.';
COMMENT ON COLUMN secure_score.action_type IS 'ActionType: Config, Review or Behavior.';
COMMENT ON COLUMN secure_score.action_url IS 'ActionUrl.';
COMMENT ON COLUMN secure_score.implementation_cost IS 'ImplementationCost: Low, Moderate or High.';
COMMENT ON COLUMN secure_score.user_impact IS 'UserImpact: Low, Moderate or High.';
COMMENT ON COLUMN secure_score.tier IS 'Tier.';
COMMENT ON COLUMN secure_score.rank IS 'Rank.';
COMMENT ON COLUMN secure_score.deprecated IS 'Deprecated.';
COMMENT ON COLUMN secure_score.threats IS 'Threats joined with "; ", NULL when empty.';
COMMENT ON COLUMN secure_score.last_modified IS 'LastModifiedDateTime.';
COMMENT ON COLUMN secure_score.raw IS 'Source record as loaded.';
COMMENT ON COLUMN secure_score.column_collections IS 'Object {column: collection_id} naming the collection that last wrote each column. Per-column latest wins: a load writes a column only when its collection is not older than the one recorded for it, so column values do not depend on ingest order. Columns no load has written (or loaded only as NULL where NULL keeps the stored value) are absent.';
COMMENT ON COLUMN secure_score.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';

-- Task 20: Azure activity logs and directory activity logs, and the timeline for the new event
-- tables.
CREATE TABLE azure_activity (
    record_key VARCHAR NOT NULL, collection_id BIGINT NOT NULL, collected_at TIMESTAMPTZ,
    event_data_id VARCHAR, event_time TIMESTAMPTZ, time_tz_assumed BOOLEAN, caller VARCHAR,
    operation_name VARCHAR, category VARCHAR, level VARCHAR, status VARCHAR, sub_status VARCHAR,
    resource_id VARCHAR, resource_group VARCHAR, resource_provider VARCHAR,
    subscription_id VARCHAR, tenant_id VARCHAR, ip VARCHAR, correlation_id VARCHAR,
    claims JSON, properties JSON, raw JSON, column_collections JSON, tz_assumed JSON
);
COMMENT ON TABLE azure_activity IS 'Azure Activity Log EventData records (Microsoft-Extractor-Suite Get-ActivityLogs ActivityLog.json and Get-DirectoryActivityLogs CSV/JSON/jsonl; four renderings of the same events deduplicate by eventDataId). An event table (fill missing): the first copy of an event wins and later copies only fill values still NULL.';
COMMENT ON COLUMN azure_activity.record_key IS 'Lower-case eventDataId.';
COMMENT ON COLUMN azure_activity.collection_id IS 'Collection that first delivered the row (fill missing: later copies never overwrite).';
COMMENT ON COLUMN azure_activity.collected_at IS 'collected_at of that collection (NULL when unknown).';
COMMENT ON COLUMN azure_activity.event_data_id IS 'eventDataId (event id), lower-case.';
COMMENT ON COLUMN azure_activity.event_time IS 'eventTimestamp.';
COMMENT ON COLUMN azure_activity.time_tz_assumed IS 'True when eventTimestamp had no timezone and UTC was assumed (the CSV culture rendering); false for the ISO JSON forms.';
COMMENT ON COLUMN azure_activity.caller IS 'caller (the UPN that performed the operation).';
COMMENT ON COLUMN azure_activity.operation_name IS 'operationName.value (Microsoft.Compute/virtualMachines/start/action).';
COMMENT ON COLUMN azure_activity.category IS 'category.value (Administrative).';
COMMENT ON COLUMN azure_activity.level IS 'level (Informational, Warning, Error, Critical, Verbose).';
COMMENT ON COLUMN azure_activity.status IS 'status.value (Succeeded, Failed, Started).';
COMMENT ON COLUMN azure_activity.sub_status IS 'subStatus.value (OK on success).';
COMMENT ON COLUMN azure_activity.resource_id IS 'resourceId of the touched resource.';
COMMENT ON COLUMN azure_activity.resource_group IS 'resourceGroupName.';
COMMENT ON COLUMN azure_activity.resource_provider IS 'resourceProviderName.value (Microsoft.Compute).';
COMMENT ON COLUMN azure_activity.subscription_id IS 'subscriptionId.';
COMMENT ON COLUMN azure_activity.tenant_id IS 'tenantId.';
COMMENT ON COLUMN azure_activity.ip IS 'httpRequest.clientIpAddress, normalized.';
COMMENT ON COLUMN azure_activity.correlation_id IS 'correlationId.';
COMMENT ON COLUMN azure_activity.claims IS 'claims string map (claim-type URI keys, e.g. http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn).';
COMMENT ON COLUMN azure_activity.properties IS 'properties string map.';
COMMENT ON COLUMN azure_activity.raw IS 'Source record as loaded.';
COMMENT ON COLUMN azure_activity.column_collections IS 'Object {column: collection_id} naming the collection that last wrote each column. Per-column latest wins: a load writes a column only when its collection is not older than the one recorded for it, so column values do not depend on ingest order. Columns no load has written (or loaded only as NULL where NULL keeps the stored value) are absent.';
COMMENT ON COLUMN azure_activity.tz_assumed IS 'Object {column: true} naming each time column whose value came without a time zone and was stored as if UTC (for example Hawk WhenChanged or AutoReply StartTime, written in the collecting host''s local time). Per column like column_collections: the load that writes a column sets or clears its entry. NULL for rows loaded before schema 7 or loads without a time column.';

CREATE OR REPLACE VIEW timeline AS
WITH ev AS (
    SELECT u.event_time, u.time_tz_assumed, 'ual_events' AS source_table, CAST(u.record_id AS VARCHAR) AS record_key,
           u.workload, u.operation, u.user_upn AS actor_upn, coalesce(u.mailbox_upn, u.object_id) AS target,
           u.client_ip AS ip, u.user_agent,
           concat_ws(' ', u.workload, u.operation, CASE WHEN u.object_id IS NOT NULL THEN 'on ' || u.object_id END) AS summary
    FROM ual_events u
    UNION ALL
    SELECT m.event_time, m.time_tz_assumed, 'mail_items_accessed', m.item_key, 'Exchange', 'MailItemsAccessed',
           m.user_upn, coalesce(m.internet_message_id, m.folder_path), m.client_ip, NULL,
           concat_ws(' ', 'MailItemsAccessed', CAST(m.access_type AS VARCHAR), m.folder_path)
    FROM mail_items_accessed m WHERE m.record_id IS NULL
    UNION ALL
    SELECT s.event_time, s.time_tz_assumed, 'signins', s.record_key, 'AzureActiveDirectory',
           CASE WHEN coalesce(s.error_code, 0) = 0 THEN 'SignInSucceeded' ELSE 'SignInFailed' END,
           coalesce(s.user_upn, s.app_name), coalesce(s.resource_name, s.app_name), s.ip, s.user_agent,
           concat_ws(' ', CAST(s.event_type AS VARCHAR), 'sign-in to', s.app_name,
                     CASE WHEN coalesce(s.error_code, 0) <> 0 THEN 'failed ' || s.error_code END)
    FROM signins s
    UNION ALL
    SELECT d.event_time, d.time_tz_assumed, 'directory_audits', d.record_key, 'AzureActiveDirectory', d.activity,
           coalesce(d.initiated_by_upn, d.initiated_by_app_name),
           coalesce(d.targets->>'$[0].UserPrincipalName', d.targets->>'$[0].userPrincipalName',
                    d.targets->>'$[0].DisplayName', d.targets->>'$[0].displayName'),
           d.initiated_by_ip, NULL, concat_ws(' ', d.category, d.activity, d.result)
    FROM directory_audits d
    UNION ALL
    SELECT t.received, t.time_tz_assumed, 'message_trace', t.record_key, 'Exchange', 'MessageTrace', t.sender,
           t.recipient, t.from_ip, NULL, concat_ws(' ', t.status, t.subject)
    FROM message_trace t
    UNION ALL
    SELECT l.event_time, l.time_tz_assumed, 'mailbox_audit_legacy', l.record_key, 'Exchange', l.operation,
           l.logon_user, l.mailbox_upn, l.client_ip, l.client_info, concat_ws(' ', l.logon_type, l.operation, l.folder_path)
    FROM mailbox_audit_legacy l
    UNION ALL
    SELECT a.run_time, a.time_tz_assumed, 'admin_audit_events', a.record_key, 'Exchange', a.cmdlet, a.caller,
           a.object_modified, a.client_ip, NULL, concat_ws(' ', a.cmdlet, a.object_modified)
    FROM admin_audit_events a
    UNION ALL
    SELECT coalesce(r.activity_time, r.detected_time), false, 'risk_detections', r.record_key, 'AzureActiveDirectory',
           r.risk_event_type, r.user_upn, NULL, r.ip, NULL, concat_ws(' ', 'risk', r.risk_level, r.risk_event_type)
    FROM risk_detections r
    UNION ALL
    SELECT a.event_time, a.time_tz_assumed, 'azure_activity', a.record_key, 'Azure', a.operation_name,
           a.caller, a.resource_id, a.ip, NULL, a.operation_name || ' ' || a.status
    FROM azure_activity a
    UNION ALL
    SELECT coalesce(s.event_time, s.created_time), false, 'security_alerts', s.record_key, NULL, s.title,
           s.affected_users[1], NULL, s.affected_ips[1], NULL, s.severity || ': ' || s.title
    FROM security_alerts s
)
SELECT ev.event_time, ev.time_tz_assumed, ev.source_table, ev.record_key,
       coalesce(
           (SELECT o.category FROM operation_catalog o
            WHERE o.operation_key = lower(trim(rtrim(trim(ev.operation), '.')))
              AND (o.workload IS NULL OR lower(o.workload) = lower(ev.workload))
            ORDER BY o.workload NULLS LAST LIMIT 1),
           CASE ev.source_table WHEN 'signins' THEN 'auth' WHEN 'risk_detections' THEN 'auth'
                                WHEN 'message_trace' THEN 'mail_flow'
                                WHEN 'azure_activity' THEN 'config_change' ELSE 'other' END::event_category
       ) AS category,
       ev.operation, ev.actor_upn, ev.target, ev.ip, i.country_iso AS ip_country, i.asn_org AS ip_asn_org,
       ev.user_agent, ev.summary, refs.source_refs
FROM ev
LEFT JOIN ip_intel i ON i.ip = ev.ip
LEFT JOIN record_source_refs refs ON refs.table_name = ev.source_table AND refs.record_key = ev.record_key;

COMMENT ON VIEW timeline IS 'One row per event record: the union of ual_events, parent-less mail_items_accessed rows, signins, directory_audits, message_trace, mailbox_audit_legacy, admin_audit_events, risk_detections, azure_activity and security_alerts, with category from operation_catalog, IP country/ASN from ip_intel, and source_refs. Deviation from spec 5.3: no finding_count column (findings arrive in Phase 6, which recreates this view); a time_tz_assumed column is added; category gains the value mail_flow for message trace rows (the spec category list has nothing for mail delivery).';
COMMENT ON COLUMN timeline.event_time IS 'Event time (UTC): ual_events.event_time, mail_items_accessed.event_time, signins.event_time, directory_audits.event_time, message_trace.received, mailbox_audit_legacy.event_time, admin_audit_events.run_time, coalesce(risk_detections.activity_time, risk_detections.detected_time), azure_activity.event_time, or coalesce(security_alerts.event_time, security_alerts.created_time).';
COMMENT ON COLUMN timeline.time_tz_assumed IS 'True when the source time had no timezone and UTC was assumed. Always false for risk_detections and security_alerts (no time_tz_assumed column: their times are Graph UTC); azure_activity carries its own time_tz_assumed.';
COMMENT ON COLUMN timeline.source_table IS 'Evidence table the row came from: ual_events, mail_items_accessed, signins, directory_audits, message_trace, mailbox_audit_legacy, admin_audit_events, risk_detections, azure_activity or security_alerts.';
COMMENT ON COLUMN timeline.record_key IS 'Key of the record in source_table (record_sources.record_key), joined against record_source_refs and, via that, verify.';
COMMENT ON COLUMN timeline.category IS 'From operation_catalog (matched on operation_key = operation_key(operation) and workload, case-insensitively, most specific workload match wins); else auth for signins/risk_detections, mail_flow for message_trace, config_change for azure_activity, other otherwise.';
COMMENT ON COLUMN timeline.operation IS 'Operation name: ual_events.operation, MailItemsAccessed for a parent-less mail_items_accessed row, SignInSucceeded/SignInFailed (Sparrow timeline name) for signins, directory_audits.activity, MessageTrace (Sparrow timeline name) for message_trace, mailbox_audit_legacy.operation, admin_audit_events.cmdlet, risk_detections.risk_event_type, azure_activity.operation_name, or security_alerts.title.';
COMMENT ON COLUMN timeline.actor_upn IS 'Who performed the action, from the source row (falls back to an app/service name where the source has no user).';
COMMENT ON COLUMN timeline.target IS 'What the action touched, from the source row. For directory_audits: TargetResources[0]''s UPN, else display name, matching either casing (Hawk''s Get-MgAuditLogDirectoryAudit is PascalCase; Microsoft-Extractor-Suite''s Graph REST JSON is camelCase).';
COMMENT ON COLUMN timeline.ip IS 'Client IP text as the source table stores it; join key into ip_intel.';
COMMENT ON COLUMN timeline.ip_country IS 'ip_intel.country_iso for ip.';
COMMENT ON COLUMN timeline.ip_asn_org IS 'ip_intel.asn_org for ip.';
COMMENT ON COLUMN timeline.user_agent IS 'User agent, when the source table records one.';
COMMENT ON COLUMN timeline.summary IS 'Short human-readable summary built from the source row''s own fields.';
COMMENT ON COLUMN timeline.source_refs IS 'record_source_refs.source_refs for (source_table, record_key); empty for a row provenance could not resolve (should not occur for ingested evidence).';
