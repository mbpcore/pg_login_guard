# pg_login_guard

By **Md. Masum Billah** ([mbpcore@gmail.com](mailto:mbpcore@gmail.com))

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

## How it decides to lock

Inside the auth hook, per connection attempt:

0. If the role name is listed in `pg_login_guard.exempt_roles`, it's
   skipped entirely — no tracking, no locking, regardless of outcome.
1. If the role is currently locked, the connection is rejected
   (`FATAL`) regardless of whether the credentials were actually
   correct.
2. Otherwise, if authentication just **succeeded**, any tracking history
   for that role is cleared.
3. Otherwise (authentication just **failed**):
   - If this role isn't already being tracked and doesn't resolve to a
     real, existing role, nothing is recorded — locking out a role that
     doesn't exist has no protective value, and this closes off the
     cheapest way to fill the tracking table with junk.
   - If the previous failure window expired, a new one starts at count 1.
   - Otherwise the counter is incremented.
   - If the counter reaches `pg_login_guard.max_attempts`, the role is
     locked for `pg_login_guard.lockout_duration`.
   - If the table is full and this role needs a new entry, the oldest
     existing entry is evicted first (preferring one that isn't
     currently locked) to make room.

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

**PostgreSQL 16, 17, and 18 — 16 is the minimum that will compile.** The
code calls `MarkGUCPrefixReserved()`, which was introduced in PG16, with
no version guard around it, so builds against PG13–15 headers fail at
compile time. (There *is* a compile-time fallback,
`#if PG_VERSION_NUM >= 150000`, for the older pre-15
`shmem_request_hook`-less shared-memory request API — but that only
covers the shared-memory setup, not the `MarkGUCPrefixReserved` call, so
it doesn't get you down to 13/14 on its own.) Of the versions that do
compile, only 16/17/18 have actually been checked against upstream
source and/or run live. `pg_login_guard.control` pins
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
sudo dnf install -y postgresql16-server postgresql16-devel gcc make krb5-devel
```

`krb5-devel` is there because [pg_login_guard.c](pg_login_guard.c)
includes `libpq/auth.h` (needed for `ClientAuthentication_hook`), which
pulls in GSSAPI/Kerberos headers whenever the target server was built
with GSSAPI support — true of PGDG's EL9 packages. **Confirmed on RHEL
9:** required to build against PostgreSQL 18's `postgresql18-devel`,
but not needed against 16 or 17 on the same OS. Since that could easily
shift with future point releases, just install it up front regardless
of version rather than relying on which majors currently need it. If
you skip it and the build fails on a missing `gssapi/gssapi.h` or
`krb5.h`, this package is why.

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
pg_login_guard.window_seconds = '5min'   # ...within this rolling window
pg_login_guard.lockout_duration = '15min'
pg_login_guard.max_tracked_roles = 1000  # requires restart to change
pg_login_guard.exempt_roles = ''         # e.g. 'postgres,replicator'
```

`exempt_roles` is a comma-separated list of role names that are never
tracked or locked, no matter how many times they fail — put your
break-glass superuser and any service/replication roles here if losing
access to them for `lockout_duration` would be worse than the brute-force
risk itself (see [Security considerations](#security-considerations)).

> **Upgrading from a build with `pg_login_guard.window` (no `_seconds`)?**
> That name was changed because `WINDOW` is a reserved word in
> PostgreSQL's SQL grammar — `SHOW pg_login_guard.window` and
> `ALTER SYSTEM SET pg_login_guard.window = ...` fail with a syntax
> error, since a bare reserved word can't appear there unquoted. Rename
> it to `pg_login_guard.window_seconds` in `postgresql.conf`. If you
> don't, PostgreSQL logs a startup warning about an unrecognized
> parameter under a reserved prefix and silently falls back to the
> 5-minute default instead of your configured value — no crash, but not
> what you asked for either.

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
  `max_attempts` times. **Mitigation available:** put your break-glass
  superuser and any service/replication roles in
  `pg_login_guard.exempt_roles` — they're then never tracked or locked,
  no matter how many times authentication against them fails.
- **Fake-username table exhaustion — largely fixed.** A tracking entry
  used to get created for *any* attempted username that reached a
  credential-checking `pg_hba.conf` line, including ones that don't
  correspond to a real role at all (PostgreSQL runs a mock
  authentication exchange for a nonexistent role specifically so a
  failure doesn't reveal whether the role exists, and that mock
  exchange still reports failure through the normal path our hook
  sees). That made it cheap for an unauthenticated attacker to fill the
  table with made-up usernames and disable tracking for every real
  role. Two fixes now apply together:
  - A new entry is only created for a username that `get_role_oid()`
    confirms is a real, existing role. Verified by testing: 5 failed
    attempts against a nonexistent username created zero tracking
    entries and caused no crash (this needed checking specifically -
    `ClientAuthentication_hook` runs before most of a backend's normal
    startup, and a catalog lookup that assumes more infrastructure is
    up than actually is could crash the connection; it didn't, most
    likely because password/SCRAM authentication itself already relies
    on the same kind of lookup - `get_role_password()` - to fetch the
    stored verifier at this same point in the connection).
  - If the table is at `max_tracked_roles` capacity when a *new* real
    role needs tracking, the oldest entry is evicted to make room
    (preferring an oldest entry that isn't currently locked, so a flood
    of new usernames can't silently lift someone's active lock early
    just to make space for itself - falls back to evicting the oldest
    *locked* entry only if every tracked entry is locked). Verified by
    testing both branches directly against a live server.

  Residual risk: an attacker who already knows (or can guess) many real
  role names can still exhaust the table with those - eviction bounds
  how long that lasts (a one-time flood no longer disables tracking
  until restart) but doesn't prevent it from happening continuously
  under sustained pressure. As before, this only applies to attempts
  that reach a `pg_hba.conf` line using a credential-checking method -
  an explicit `reject` line, or no matching line at all (PostgreSQL's
  implicit reject), never reaches `ClientAuthentication()`'s
  hook-invocation code, so that traffic can't contribute to this at
  all.
- **Fixed: `max_tracked_roles` wasn't actually a hard cap.** Found while
  testing the eviction fix above: a dynahash table created via
  `ShmemInitHash` does not fail `HASH_ENTER` right at the `max_size`
  hint passed to it - that value only sizes the initial shared-memory
  request, and the table can silently grow well past it into whatever
  slack that sizing left. Confirmed by testing: with
  `max_tracked_roles = 10`, the table kept accepting new distinct roles
  past 60 entries without complaint or eviction. Fixed by checking
  `hash_get_num_entries()` against `max_tracked_roles` explicitly before
  inserting, rather than relying on `HASH_ENTER_NULL` to fail on its
  own - which also means the eviction logic above actually gets a
  chance to run at the threshold you configure, instead of some much
  larger and less predictable point.
- `pg_login_guard_status()` is superuser-only by default (as of the
  `REVOKE ALL ... FROM PUBLIC` in the install script) — earlier it was
  left PUBLIC-readable, which handed any authenticated user in the
  database role names, attempt counts, and exact lock-expiry timestamps
  for reconnaissance purposes. `GRANT` it explicitly to a monitoring
  role if you want non-superusers to see it.
- **Fixed: a full-table `pg_login_guard_status()` call could crash the
  whole server.** When the tracking table was completely full, the
  status function's `hash_seq_search()` loop stopped right at capacity
  without the one further call that would've returned `NULL` and
  self-terminated the scan — an "abandoned" scan per dynahash's
  documented contract, which must be explicitly closed with
  `hash_seq_term()` or it leaks a slot in that backend's fixed-size
  (100-slot) active-scan table. Confirmed by testing: repeatedly calling
  `pg_login_guard_status()` in one session while the table was full
  eventually threw `"too many active hash_seq_search scans"` against
  our own hash table, then cascaded into the same error against
  PostgreSQL's *internal* `Portal hash` table, then an abort-loop, then
  `PANIC: ERRORDATA_STACK_SIZE exceeded` — which crashes the whole
  server (PostgreSQL treats any backend `PANIC` as a possible
  shared-memory corruption signal and restarts every process). A
  negative control confirmed the unfixed code reproduces this
  reliably, and the fix (an explicit `hash_seq_term()` call when the
  loop hits capacity) survives 300 consecutive full-table calls in one
  session with no leak and no crash. Practically: this only triggers
  while the table is at 100% capacity, which is also exactly the
  fake-username-exhaustion scenario above — so it mattered most for
  anyone actively monitoring `pg_login_guard_status()` during an
  ongoing attack, which is a fairly likely thing to be doing at exactly
  that moment.

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
- Auth methods other than `scram-sha-256` (and the confirmed
  `reject`/implicit-reject bypass) haven't been individually verified to
  reach `ClientAuthentication_hook` the same way — `cert`, `gss`,
  `ldap`, `radius`, `pam`, `ident`, and `peer` are untested.
- Doesn't reduce server load during an attack. The hook runs *after*
  PostgreSQL completes the full authentication handshake for that
  connection, locked account or not - being locked skips nothing on the
  server's side, it just prevents the attempt from ultimately
  succeeding. Pair with `pg_hba.conf` scoping, a firewall/security-group
  rate limit, or a connection limiter (PgBouncer, `max_connections`) if
  connection-flood resistance is also a goal.

## Author

**Md. Masum Billah**
Contact: [mbpcore@gmail.com](mailto:mbpcore@gmail.com)

## License

[MIT](LICENSE) — Copyright (c) 2026 Md. Masum Billah.
