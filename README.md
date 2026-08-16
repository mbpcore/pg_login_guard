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

Built and exercised end-to-end against PostgreSQL 18.6 (MSYS2
`mingw-w64-x86_64-postgresql`, GCC 16.2.0): 3 real failed SCRAM logins
trip the lock, a 4th attempt with the *correct* password is rejected
with the expected `FATAL`/`DETAIL`/`HINT`, the lock lifts on its own
once `lockout_duration` elapses, and `pg_login_guard_unlock()` lifts it
on demand. `make installcheck` passes. See
[Supported PostgreSQL versions](#supported-postgresql-versions) for
what's been checked on 16/17, and [Build & install](#build--install) to
reproduce any of this yourself.

A real bug was found and fixed along the way: the original code used
`RequestNamedLWLockTranche()` / `GetNamedLWLockTranche()` for its lock.
On this Windows/EXEC_BACKEND build, the bookkeeping array that
mechanism depends on didn't make it into child processes (checkpointer,
io workers) reliably, crashing them at startup with access violations
the moment any preloaded module (not just this one) called
`GetNamedLWLockTranche()` outside of the process that first created it.
The fix embeds the `LWLock` directly inside our own
`ShmemInitStruct`-allocated state and identifies it via
`LWLockNewTrancheId()`/`LWLockRegisterTranche()` instead — see the
comment above `LoginGuardShmemState` in [pg_login_guard.c](pg_login_guard.c).
This is very likely a Linux/WSL non-issue; it was only reproduced (and
fixed) against the specific MSYS2 Windows package above.

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
pg_login_guard.control                      extension control file
pg_login_guard.c                            C implementation (the hook + admin functions)
sql/pg_login_guard--1.0.sql                 SQL objects installed by CREATE EXTENSION
Makefile                                    PGXS build file
test/sql/pg_login_guard_admin.sql           pg_regress smoke test (admin functions only)
test/expected/pg_login_guard_admin.out      expected output for the smoke test
```

## Build & install

### Supported PostgreSQL versions

**PostgreSQL 16, 17, and 18.** The code targets the modern
`shmem_request_hook` (PG15+) shared-memory API and `MarkGUCPrefixReserved`
(PG16+), with a compile-time fallback (`#if PG_VERSION_NUM >= 150000`) for
older 13–14 servers using the pre-15 shared-memory request API — so it
*should* build on 13+, but only 16/17/18 have actually been checked
against upstream source and/or run live. `pg_login_guard.control` pins
`default_version = '1.0'` regardless of server version; there's nothing
version-specific in the SQL.

You need two things, matched to each other: a PostgreSQL **server
development package** for your target major version (it ships
`pg_config`, headers, and the PGXS build makefiles) and a **C compiler**
that's ABI-compatible with the PostgreSQL binary you'll load the
extension into. Pick the section for your platform below.

### Linux — Debian / Ubuntu

Ubuntu's/Debian's own repos often lag behind or only carry one PG major
version. Use the official PGDG apt repository instead so you can pick
16, 17, or 18 explicitly:

```bash
sudo apt install -y postgresql-common ca-certificates
sudo /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh
sudo apt update

# pick ONE of these, matching the server you'll load the extension into:
sudo apt install -y postgresql-16 postgresql-server-dev-16 build-essential
sudo apt install -y postgresql-17 postgresql-server-dev-17 build-essential
sudo apt install -y postgresql-18 postgresql-server-dev-18 build-essential
```

Then build and install:

```bash
cd pg_login_guard
make                # uses `pg_config` on PATH — if you have multiple
                     # versions installed, run e.g.
                     # make PG_CONFIG=/usr/lib/postgresql/17/bin/pg_config
sudo make install
```

### Linux — RHEL / Rocky / AlmaLinux (and other EL-family)

Via the official PGDG yum/dnf repository (example for EL9 — swap
`EL-9-x86_64` for your release from [yum.postgresql.org](https://yum.postgresql.org/)
if different, and `16` for `17`/`18`):

```bash
sudo dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm
sudo dnf -qy module disable postgresql   # step aside for PGDG's own versioned packages
sudo dnf install -y postgresql16-server postgresql16-devel gcc make
```

```bash
cd pg_login_guard
export PG_CONFIG=/usr/pgsql-16/bin/pg_config   # adjust for your version
make PG_CONFIG=$PG_CONFIG
sudo make install PG_CONFIG=$PG_CONFIG
```

### macOS — Homebrew

```bash
brew install postgresql@16   # or @17 / @18
export PATH="$(brew --prefix postgresql@16)/bin:$PATH"

cd pg_login_guard
make
make install     # Homebrew-owned prefix, usually no sudo needed
```

### Windows — MSYS2/MinGW-w64

This is the path actually used to build and test this extension (against
the version MSYS2 currently packages — 18.6 as of this writing; MSYS2 is
a rolling repo and doesn't offer older majors side by side, so this route
is really only for "whatever's current," i.e. 18 today). Install
[MSYS2](https://www.msys2.org/), then from an **MSYS2 MinGW64** shell:

```bash
pacman -Syu                          # first run: it'll ask to close & reopen the shell, then re-run this
pacman -S --needed mingw-w64-x86_64-postgresql mingw-w64-x86_64-gcc make mingw-w64-x86_64-diffutils
```

(`diffutils` is only needed to run `make installcheck`.) Then, from that
same MinGW64 shell (make sure `/mingw64/bin` is on `PATH`, which it is
by default in that shell):

```bash
cd /d/pg_extension/pg_login_guard
make
make install
```

This installs a real PostgreSQL server (`pg_config`, `initdb`, `pg_ctl`,
`psql`, ...) matched to the same MinGW GCC used to build the extension —
no compiler-ABI mismatch. See [Windows gotchas](#windows-gotchas-msys2)
below for environment quirks you'll hit when standing up a test cluster
this way.

If you specifically need Windows + PG16 or PG17 (not whatever MSYS2
currently packages), or you already have an EDB-installed (MSVC-built)
PostgreSQL on `PATH`: plain PGXS `make` will generally *not* link against
it, since MinGW `gcc` and MSVC have incompatible ABIs. Either build with
MSVC via `nmake` and PostgreSQL's `src/tools/msvc` scripts, or — much
less friction — install that PG version under WSL and use the Linux
instructions above.

### Windows gotchas (MSYS2)

Hit while standing up a local test cluster; not specific to this
extension, but worth knowing:

- **PG18's io-worker subsystem crashes on this build.** If you see
  `io worker (PID ...) was terminated by exception 0xC0000005` in the
  log right after startup, add `io_method = sync` to `postgresql.conf`.
  Unrelated to `pg_login_guard` — reproduces with *no* preload libraries
  at all.
- **No Unix-domain socket by default**, so `psql` with no `-h` fails
  with "Connection refused" even though `pg_hba.conf` has a `local`
  line. Connect over TCP (`-h 127.0.0.1`) instead, or set
  `unix_socket_directories` and confirm your Windows version supports
  `AF_UNIX`.
- **The `postgres` superuser has no password after `initdb`.** If
  `pg_hba.conf` requires `scram-sha-256` for TCP before you've set one,
  `psql` blocks forever on a password prompt it never receives (no TTY).
  Set `pg_hba.conf` to `trust` first, `pg_ctl reload`, run
  `ALTER ROLE postgres PASSWORD '...'`, then switch back to
  `scram-sha-256` and reload again.

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

If it reports only whitespace/column-width diffs against your build,
copy `test/results/pg_login_guard_admin.out` over
`test/expected/pg_login_guard_admin.out` and re-run to confirm a clean
pass.

## Security considerations

- **Any account (including `postgres`) can be locked out by someone with
  no credentials at all** — that's the fundamental nature of a lockout
  policy, not a bug specific to this extension (the same is true of
  fail2ban, AD account-lockout policies, etc.). Anyone who knows a role
  name can lock it by deliberately failing to authenticate as it
  `max_attempts` times. Weigh this before enabling for roles where
  availability matters more than brute-force resistance, and consider
  excluding your break-glass superuser role once an allowlist exists
  (see Known limitations below).
- **Fake-username table exhaustion.** The shared-memory tracking table
  has a fixed capacity (`pg_login_guard.max_tracked_roles`, default
  1000). `ClientAuthentication_hook` fires — and a tracking entry gets
  created — for *any* attempted username, including ones that don't
  correspond to a real role. An unauthenticated remote attacker can
  send `max_tracked_roles` failed connections using that many distinct
  made-up usernames (cheap — no valid credentials needed for any of
  them) to fill the table. Once full, new entries are silently dropped
  (a `WARNING` is logged) — meaning brute-force tracking is effectively
  disabled for every *real* role until a restart or enough entries
  clear naturally. There's no eviction of stale/never-succeeded entries
  today. Practical mitigations: size `max_tracked_roles` well above your
  real role count so this requires a large sustained attempt volume,
  watch the server log for the `tracking table is full` warning, and/or
  restrict which addresses can attempt authentication at all via
  `pg_hba.conf`. A real fix would be to only create a tracking entry for
  usernames that resolve to an existing role, or add LRU eviction —
  both are non-trivial from inside this hook (catalog lookups need a
  transaction context that isn't reliably available this early) and
  aren't implemented yet.
- `pg_login_guard_status()` is superuser-only by default (as of the
  `REVOKE ALL ... FROM PUBLIC` in the install script) — earlier it was
  left PUBLIC-readable, which handed any authenticated user in the
  database role names, attempt counts, and exact lock-expiry timestamps
  for reconnaissance purposes. `GRANT` it explicitly to a monitoring
  role if you want non-superusers to see it.

## Performance

Per connection attempt, the hook does one hash-table lookup/insert under
a single shared-memory `LWLock`, held exclusively for a handful of
`memcpy`/comparison operations — no disk I/O, no catalog access, no
extra network round trip. That's negligible next to the cost of a
SCRAM handshake and process/backend startup itself. The one shared lock
is a global serialization point across all connecting backends, so it
could show up in profiles on workloads doing very high-frequency new
connections (thousands/sec, e.g. an app connecting without a pooler) —
but the critical section is short enough that this is unlikely to be
the bottleneck before other server limits are. `pg_login_guard_status()`
holds a shared lock for a full table scan, proportional to
`max_tracked_roles`; harmless at the default (1000) but worth knowing
if you raise that a lot and poll `status()` frequently. Steady-state
shared memory footprint is small and fixed at startup (~90KB at the
default `max_tracked_roles`, scaling linearly with it).

## Known limitations / ideas for later

- State lives in shared memory only: a server restart clears all
  counters and locks. Fine for brute-force mitigation, not an audit log.
- Not replicated — on a physical standby, auth attempts against the
  standby are tracked independently from the primary.
- No per-IP tracking (only per-role); an attacker rotating through many
  roles from one IP isn't slowed down. Could be extended to key on
  `(rolename, client_addr)` or add a separate per-IP table.
- No allowlist for exempting specific roles (e.g. replication roles, a
  break-glass superuser) from lockout — everyone is tracked today.
