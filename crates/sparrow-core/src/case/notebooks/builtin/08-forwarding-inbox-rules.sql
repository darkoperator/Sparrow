-- Inbox rules that forward, redirect, delete or move mail
-- The classic business email compromise rule hides replies (delete, move to an obscure folder,
-- mark as read) or sends mail out (forward, redirect). Disabled rules are listed too.
SELECT mailbox_upn AS mailbox, name, enabled, kind,
       forward_to, forward_as_attachment_to, redirect_to,
       delete_message, soft_delete, move_to_folder, mark_as_read,
       from_addresses, subject_contains, subject_or_body_contains, description
FROM inbox_rules
WHERE coalesce(len(forward_to), 0) > 0
   OR coalesce(len(forward_as_attachment_to), 0) > 0
   OR coalesce(len(redirect_to), 0) > 0
   OR delete_message OR soft_delete OR mark_as_read
   OR move_to_folder IS NOT NULL
ORDER BY mailbox, name;
