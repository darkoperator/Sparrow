-- 0002: the subject a file is about, so byte-identical files for different subjects are not deduplicated.
ALTER TABLE source_files ADD COLUMN subject VARCHAR;

COMMENT ON COLUMN source_files.subject IS 'Subject taken from the file path (user UPN, IP address, message id or operation), NULL if the artifact has none.';
