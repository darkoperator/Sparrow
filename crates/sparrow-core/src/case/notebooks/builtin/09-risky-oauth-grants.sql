-- OAuth grants with mail or offline access
-- Apps that can read or send mail, reach every mailbox, or keep access without the user
-- (offline_access). Apps without a verified publisher come first, then the newest grants.
SELECT client_name, client_id, permission, CAST(permission_type AS VARCHAR) AS permission_type,
       consent_type, principal_upn, resource_name, publisher, verified_publisher, created
FROM oauth_grants
WHERE permission ILIKE 'mail.%' OR permission ILIKE 'mailboxsettings.%'
   OR permission ILIKE '%offline_access%' OR permission ILIKE '%full_access_as_app%'
   OR permission ILIKE 'ews.%' OR permission ILIKE 'imap.%' OR permission ILIKE 'smtp.%'
ORDER BY coalesce(verified_publisher, '') = '' DESC, created DESC NULLS LAST, client_name;
