-- Listing objects shared with a user (e.g. GET /buckets) joins
-- access_control_entries on principal and permission, then discards history
-- entries. History entries hold almost all ACEs, so that scan grows with every
-- write. This partial index covers only the non-history ACEs, and matches the
-- HISTORY_EXCLUSION_CONDITION predicate used by get_accessible_objects().
--
-- On large tables, build it beforehand without blocking writes; this
-- migration is then a no-op:
--   CREATE INDEX CONCURRENTLY idx_ace_principal_nohistory ...
CREATE INDEX IF NOT EXISTS idx_ace_principal_nohistory
    ON access_control_entries(principal, permission) INCLUDE (object_id)
    WHERE object_id NOT LIKE '%/history/%';

INSERT INTO metadata (name, value) VALUES ('permission_schema_version', '3');
