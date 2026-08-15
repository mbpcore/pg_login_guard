# pg_login_guard

A small PostgreSQL extension that locks a role out after too many failed
login attempts in a row, fail2ban-style:

> If role `X` fails to authenticate `max_attempts` times within a rolling
> `window`, it is locked for `lockout_duration` — further connection
> attempts (even with the correct password) are rejected until the
> lockout expires or an administrator unlocks it manually.

It hooks into PostgreSQL's `ClientAuthentication_hook`, so it sees every
real authentication attempt (password, SCRAM, md5, etc.) for every role,
not just application-level logins. State is kept in a fixed-size shared
memory table (no extra catalog tables, no writes-during-auth headaches),
guarded by a single lightweight lock. It resets on server restart, same
as fail2ban's in-memory ban list.

## Status

This is a fresh scaffold — the C code is written and believed correct,
but it has **not yet been compiled or tested against a running
PostgreSQL server** in this environment (no PostgreSQL installation or C
toolchain was present on this machine at project-creation time). Build
it and run the smoke test before relying on it. See
[Build & install](#build--install) below.

## How it decides to lock

Inside the auth hook, per connection attempt:

1. If the role is currently locked, the connection is rejected
   (`FATAL`) regardless of whether the credentials were actually
   correct.
2. Otherwise, if authentication just **succeeded**, any tracking history
   for that role is cleared.
3. Otherwise (authentication just **failed**):
   - If the previous failure window expired, a new one starts at count 1.
   - Otherwise the counter is incremented.
   - If the counter reaches `pg_login_guard.max_attempts`, the role is
     locked for `pg_login_guard.lockout_duration`.

## Files

```
pg_login_guard.control            extension control file
pg_login_guard.c                  C implementation (the hook + admin functions)
sql/pg_login_guard--1.0.sql       SQL objects installed by CREATE EXTENSION
Makefile                          PGXS build file
test/pg_login_guard_admin.sql     pg_regress smoke test (admin functions only)
test/pg_login_guard_admin.out     expected output for the smoke test
```

## Build & install

You need PostgreSQL's server development files (`pg_config` on `PATH`)
and a C compiler matching the one PostgreSQL itself was built with.

### Option A — WSL / Linux (recommended, least friction)

```bash
sudo apt install postgresql-server-dev-17 build-essential   # match your PG version
cd pg_login_guard
make
sudo make install
```

### Option B — Windows with MSYS2/MinGW-w64

Install PostgreSQL for Windows (EDB installer, includes `pg_config` and
headers) and MSYS2 with the `mingw-w64-x86_64-toolchain` group. From a
MinGW64 shell, with PostgreSQL's `bin` directory on `PATH`:

```bash
cd /d/pg_extension/pg_login_guard
make
make install
```

If `pg_config --pgxs` or the build fails due to compiler mismatch
(MSVC-built PostgreSQL vs. MinGW `gcc`), building under WSL against a
Linux PostgreSQL install is the more reliable path — or build with MSVC
via `nmake` and PostgreSQL's `src/tools/msvc` build scripts.

## Configure

`pg_login_guard` allocates shared memory and installs its hook at
`postmaster` start, so it **must** be loaded via
`shared_preload_libraries`. In `postgresql.conf`:

```conf
shared_preload_libraries = 'pg_login_guard'

# Optional tuning (defaults shown):
pg_login_guard.enabled = on
pg_login_guard.max_attempts = 5          # failed attempts allowed
pg_login_guard.window = '5min'           # ...within this rolling window
pg_login_guard.lockout_duration = '15min'
pg_login_guard.max_tracked_roles = 1000  # requires restart to change
```

Restart PostgreSQL, then in any database:

```sql
CREATE EXTENSION pg_login_guard;
```

(This just installs the three admin-facing SQL functions below — the
locking logic runs regardless of whether the extension is "created" in
any particular database, since the hook is server-wide. Creating the
extension is only needed where you want to query/manage state via SQL.)

## Using it

```sql
-- See everyone currently being tracked (has a recent failure, or is locked):
SELECT * FROM pg_login_guard_status();

--  role_name | failed_attempts | window_started_at      | locked_until
-- -----------+------------------+-------------------------+-------------------------
--  alice     |                3 | 2026-08-15 10:00:01+00  |
--  bob       |                5 | 2026-08-15 10:01:40+00  | 2026-08-15 10:16:40+00

-- Manually unlock a role before its lockout expires (superuser only):
SELECT pg_login_guard_unlock('bob');

-- Forget all tracking history for a role (superuser only):
SELECT pg_login_guard_reset('bob');
```

## Manual test with psql

```bash
# from a machine that can reach the server, using a role with a known-wrong password:
for i in 1 2 3 4 5; do
  PGPASSWORD=wrong psql -h <host> -U alice -c 'select 1'
done
# 6th attempt (even with the *correct* password) should now fail with:
#   FATAL:  role "alice" is temporarily locked due to repeated failed login attempts
PGPASSWORD=<correct password> psql -h <host> -U alice -c 'select 1'
```

Check the server log for the `pg_login_guard: role "alice" locked for ...`
message, and `SELECT * FROM pg_login_guard_status();` to confirm.

## Running the regression test

```bash
make installcheck   # requires a running server matching pg_config, and
                     # PGUSER with rights to CREATE EXTENSION
```

`test/pg_login_guard_admin.out` was hand-written to match expected
`psql` formatting; if `make installcheck` reports only whitespace/column
-width diffs, copy `results/pg_login_guard_admin.out` over
`test/pg_login_guard_admin.out` and re-run to confirm a clean pass.

## Known limitations / ideas for later

- State lives in shared memory only: a server restart clears all
  counters and locks. Fine for brute-force mitigation, not an audit log.
- Not replicated — on a physical standby, auth attempts against the
  standby are tracked independently from the primary.
- No per-IP tracking (only per-role); an attacker rotating through many
  roles from one IP isn't slowed down. Could be extended to key on
  `(rolename, client_addr)` or add a separate per-IP table.
- No allowlist for exempting specific roles (e.g. replication roles)
  from lockout — everyone is tracked today.
