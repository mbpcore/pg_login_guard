-- Basic smoke test for the admin-facing SQL functions.
-- This does NOT exercise the ClientAuthentication_hook itself (that
-- requires real connection attempts from an external client - see
-- README.md for a manual walkthrough with psql).

CREATE EXTENSION pg_login_guard;

-- No failed logins recorded yet in a fresh session.
SELECT * FROM pg_login_guard_status();

-- Operations on a role with no tracking entry are no-ops that return false.
SELECT pg_login_guard_unlock('no_such_role');
SELECT pg_login_guard_reset('no_such_role');

DROP EXTENSION pg_login_guard;
