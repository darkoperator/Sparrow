# Key tables and their columns

A summary of the tables you query most, taken from the schema comments of this version. The authority is the
command: `sparrow schema --case case.duckdb --table <TABLE> --json` prints every column with its type and comment,
and `sparrow schema --case case.duckdb --json` lists every table. Skipped here: `raw`, `column_collections`,
`tz_assumed` (provenance bookkeeping) and `collection_id` / `collected_at` where they are not useful.

Times are UTC (`TIMESTAMP WITH TIME ZONE`). UPNs and ids are stored lower-case. `ip` columns are text. `VARCHAR[]`
columns are lists.

## signins (Entra ID sign-ins; one row per sign-in id)

| Column | Meaning |
| --- | --- |
| `record_key`, `signin_id` | Sign-in id (lower-case). |
| `event_time` | Sign-in time. |
| `event_type` | interactive, noninteractive, service_principal or managed_identity. |
| `is_interactive` | Interactive sign-in. |
| `user_upn`, `user_id`, `user_display_name` | The user. |
| `app_id`, `app_name` | Client application. |
| `resource_id`, `resource_name` | Resource (API) signed in to. |
| `ip` | Client IP address. |
| `asn` | Autonomous system number of the client IP (portal exports). Prefer `ip_intel.asn`. |
| `location` | Struct: city, state, country, latitude, longitude. |
| `user_agent`, `client_app` | Agent string; Browser, Mobile Apps and Desktop clients, IMAP4, ... |
| `status`, `error_code`, `failure_reason` | Success, Failure or Interrupted; 0 is success, 50126 invalid password, 50074 strong authentication required. |
| `risk_level_during`, `risk_level_aggregated`, `risk_state`, `risk_detail`, `risk_event_types` | Entra risk (none, low, medium, high); risk_state includes atRisk and confirmedCompromised. |
| `auth_requirement`, `mfa_result`, `mfa_detail`, `auth_methods` | single or multi-factor, MFA outcome and methods. |
| `session_id` | Groups the sign-ins of one session (an AiTM pivot). Absent in some collectors. |
| `ca_status`, `ca_policies` | Conditional Access result and policies. |
| `device` | Struct: device_id, display_name, os, browser, is_compliant, is_managed, trust_type. |
| `token_issuer_type`, `incoming_token_type` | Token details (portal). |

## ual_events (unified audit log; one row per AuditData Id)

| Column | Meaning |
| --- | --- |
| `record_id` | AuditData Id. |
| `event_time` | CreationTime. |
| `record_type`, `record_type_name`, `workload` | Kind of record; Exchange, SharePoint, AzureActiveDirectory, ... |
| `operation` | New-InboxRule, Set-InboxRule, UpdateInboxRules, MailItemsAccessed, Send, FileDownloaded, UserLoggedIn, Consent to application., ... |
| `result_status` | Succeeded, Failed, ... |
| `user_upn` | The actor (UserId). |
| `mailbox_upn` | The mailbox the action touched. |
| `client_ip` | First of ClientIP, ClientIPAddress, ActorIpAddress; text. |
| `user_agent`, `session_id`, `app_id`, `client_app_id` | Client details. |
| `object_id` | Target object (mailbox\rule, file URL, ...). |
| `parameters` | Map of cmdlet parameters and operation properties, e.g. `parameters['ForwardTo']`. |
| `audit_data` | The whole AuditData object as JSON. |
| `data_completeness` | full or partial (a lossy source form). |

## inbox_rules (state of inbox rules at collection time)

`mailbox`, `name` (single characters and dots are red flags), `rule_identity`, `kind` (inbox or sweep), `enabled`,
`priority`, `forward_to`, `forward_as_attachment_to`, `redirect_to` (lists of recipients), `delete_message`,
`soft_delete`, `move_to_folder`, `copy_to_folder`, `mark_as_read`, `stop_processing`, `from_addresses`,
`subject_contains`, `body_contains`, `subject_or_body_contains` (lists), `has_attachment`, `description`, `source`
(hawk, exo or graph). The state has no creation time or creating address: use `ual_events` or `timeline` for those.

## mailboxes (mailbox settings, merged per column)

`upn`, `primary_smtp_address`, `recipient_type`, `forwarding_smtp_address` (as recorded, e.g. smtp:x@example.test),
`forwarding_address`, `deliver_and_forward`, `audit_enabled`, `audit_bypass_enabled`, `effective_audit_state`,
`pop_enabled`, `imap_enabled`, `ews_enabled`, `owa_enabled`, `activesync_enabled`, `mapi_enabled`,
`auto_reply_state`, `when_changed`.

## oauth_grants (consents; one row per client, resource, permission and principal)

`permission_type` (delegated or application), `client_id`, `client_name`, `resource_name`, `permission` (Mail.Read,
offline_access, ...), `consent_type` (AllPrincipals is admin consent, Principal is user consent), `principal_id`,
`principal_name`, `principal_upn` (not always filled), `risk_category` (Hawk's own heuristic), `publisher`,
`verified_publisher`, `created`. Note `client_id` is the service principal object id here; match an application by
`client_name` or check `applications.app_id`.

## ip_intel (one row per distinct IP in the event tables)

`ip` (join key), `country_iso`, `country`, `city`, `latitude`, `longitude`, `asn`, `asn_org`, `is_hosting` (known
hosting, cloud or VPS ASN; NULL when the ASN is unknown), `hosting_provider`, `is_microsoft` (Microsoft 365 service
ranges), `microsoft_service_area`, `is_private`. Location and ASN are empty when the case was ingested without a
GeoIP folder: check before you reason from them.

## findings and finding_evidence

`findings`: `finding_id`, `rule_id`, `rule_version`, `severity` (info, low, medium, high, critical), `title`,
`actor_upn`, `first_seen`, `last_seen`, `status` (new, in_review, confirmed, false_positive, benign,
needs_more_data), `disposition_reason`, `created_by`, `assigned_to`, `rule_updated`, `decided_by`, `review_state`.
`finding_evidence`: `finding_id`, `source_table`, `record_key`, `event_time`, `role` (trigger or context), `context`
(JSON from the rule).

## timeline (a view: one row per event record across the evidence tables)

`event_time`, `source_table`, `record_key` (the key of the record in its source table; use it with `verify`),
`category` (auth, mail_read, mail_send, mail_rule, forwarding, permission, app_consent, app_credential, role_change,
mfa_change, file_access, ...), `operation`, `actor_upn`, `target`, `ip`, `ip_country`, `ip_asn_org`, `user_agent`,
`summary`, `source_refs` (files and lines), `finding_count`, `finding_ids`.

## cloud_services (tenant-wide connectors; derived)

One row per tenant, application id and hosting ASN: `tenant_key`, `app_id`, `asn`, `hosting_users` (at least 5),
`hosting_days` (at least 3), `signins`, `hosting_signins`. A pair qualifies when at least five users signed in to the
application from that hosting ASN on at least three days and those sign-ins are most of the application's successes,
unless sprayed users or credential failures disqualify it. Microsoft first-party applications are never listed.
Detections skip the sign-ins of a listed pair: an application NOT listed may still be a connector (too few users or
days in the capture).

## spray_sources (password-spray addresses; derived)

One row per tenant and address: `tenant_key`, `ip`, `users_targeted`, `failures`, `first_failure`, `last_failure`,
`failed_only_users`, `success_users`, `sprayed_users`, `takeover_users` (sprayed users who later succeeded from the
address: the account was taken over). An office NAT where users mistype and then succeed is not a source.

## Other tables worth a look

`directory_audits` (Entra audit: consents, role changes, MFA registrations), `admin_audit_events` (Exchange admin
audit, Hawk 3), `risk_detections`, `app_credentials` (secrets and certificates), `applications`,
`mail_items_accessed`, `message_trace`, `collections` and `source_files` (what was ingested). Look their columns up
with `sparrow schema`.
