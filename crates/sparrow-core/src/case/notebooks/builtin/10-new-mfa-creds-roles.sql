-- New MFA methods, app credentials and role changes, by time
-- Persistence: security info registered or changed, secrets and certificates added to apps,
-- and directory or Exchange roles granted. Newest first; the app credentials come from the
-- credential's start time.
SELECT time, what, operation, actor, target, summary
FROM (
    SELECT event_time AS time, CAST(category AS VARCHAR) AS what, operation,
           actor_upn AS actor, target, summary
    FROM events
    WHERE CAST(category AS VARCHAR) IN ('mfa_change', 'app_credential', 'role_change')
    UNION ALL
    SELECT start_time, 'app_credential', 'credential valid from', NULL, app_name,
           CAST(cred_type AS VARCHAR) || ' ' || coalesce(key_id, '')
    FROM app_credentials
)
ORDER BY time DESC NULLS LAST;
