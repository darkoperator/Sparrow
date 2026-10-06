-- Migration 19: comments on schema_migrations, the one table without them (the migration runner creates it before
-- migration 1), so `sparrow schema` describes every table and column `sparrow query` can read (comments only; no
-- schema or data change).

COMMENT ON TABLE schema_migrations IS 'The schema migrations applied to this case, one row per migration, written by the migration runner in the same transaction as the migration. max(version) is the case''s schema version: a read refuses a case older than the build (run `sparrow upgrade`) or newer than it.';
COMMENT ON COLUMN schema_migrations.version IS 'Migration number (1, 2, ...), the schema version the case has once the migration is applied.';
COMMENT ON COLUMN schema_migrations.name IS 'The migration''s short name (for example derived_relation_comments).';
COMMENT ON COLUMN schema_migrations.applied_at IS 'When this case applied the migration (the database clock, UTC).';
