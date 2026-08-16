-- pg_login_guard--1.0.sql

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_login_guard" to load this file. \quit

-- pg_login_guard_status(): one row per role currently being tracked
-- (i.e. that has at least one failed login attempt recorded since the
-- last successful login or window expiry).
CREATE FUNCTION pg_login_guard_status(
    OUT role_name        text,
    OUT failed_attempts   int,
    OUT window_started_at timestamptz,
    OUT locked_until      timestamptz
) RETURNS SETOF record
AS 'MODULE_PATHNAME', 'pg_login_guard_status'
LANGUAGE C STABLE STRICT PARALLEL SAFE;

COMMENT ON FUNCTION pg_login_guard_status() IS
    'Show roles currently tracked by pg_login_guard, their failed-attempt count and lock status';

-- pg_login_guard_unlock(role_name): clear a lock (and reset its counter)
-- for the given role. Returns true if the role had a tracking entry.
CREATE FUNCTION pg_login_guard_unlock(role_name text) RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_login_guard_unlock'
LANGUAGE C VOLATILE STRICT;

COMMENT ON FUNCTION pg_login_guard_unlock(text) IS
    'Manually unlock a role that was locked by pg_login_guard';

-- pg_login_guard_reset(role_name): forget all tracking state for a role
-- (equivalent to it never having had a failed login).
CREATE FUNCTION pg_login_guard_reset(role_name text) RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_login_guard_reset'
LANGUAGE C VOLATILE STRICT;

COMMENT ON FUNCTION pg_login_guard_reset(text) IS
    'Remove all pg_login_guard tracking state for a role';

REVOKE ALL ON FUNCTION pg_login_guard_unlock(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION pg_login_guard_reset(text) FROM PUBLIC;

-- Not secrets, but role names + attempt counts + lock-expiry timestamps
-- are still reconnaissance value (which accounts exist/are under attack,
-- and exactly when a lock lifts) that an arbitrary authenticated user in
-- this database has no need to see. Default to superuser-only, like the
-- two functions above; GRANT to a specific monitoring role if wanted, e.g.:
--   GRANT EXECUTE ON FUNCTION pg_login_guard_status() TO pg_monitor;
REVOKE ALL ON FUNCTION pg_login_guard_status() FROM PUBLIC;
