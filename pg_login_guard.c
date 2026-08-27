/*-------------------------------------------------------------------------
 *
 * pg_login_guard.c
 *      Lock a role after N failed login attempts within a rolling
 *      time window (a small "fail2ban for PostgreSQL roles").
 *
 * State is kept in a fixed-size shared-memory hash table, one entry
 * per role name currently being tracked, guarded by a single LWLock.
 * Nothing is written to the catalog, so this works even before the
 * database is otherwise usable and needs no SPI/transaction dance
 * inside the authentication hook.
 *
 * Must be loaded via shared_preload_libraries.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "fmgr.h"
#include "funcapi.h"
#include "libpq/auth.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/hsearch.h"
#include "utils/timestamp.h"

PG_MODULE_MAGIC;

/* ---- shared-memory entry ---- */
typedef struct LoginGuardEntry
{
    char        rolename[NAMEDATALEN];  /* hash key */
    int32       attempt_count;
    TimestampTz window_started;
    TimestampTz locked_until;           /* 0 = not locked */
} LoginGuardEntry;

/*
 * A single ad hoc LWLock, allocated inside our own shared-memory struct
 * and identified via LWLockNewTrancheId()/LWLockRegisterTranche(), rather
 * than via RequestNamedLWLockTranche()/GetNamedLWLockTranche(). The named-
 * tranche path relies on postmaster.c copying a backend-local bookkeeping
 * array to EXEC_BACKEND child processes (Windows); that copy did not
 * happen reliably for third-party preloaded modules when this was tested
 * (checkpointer/io-worker crashed on GetNamedLWLockTranche() at startup).
 * A lock embedded in our own ShmemInitStruct-allocated memory needs no
 * such per-process bookkeeping to be re-synchronized, since it's plain
 * shared data that every process reattaches to identically.
 */
typedef struct LoginGuardShmemState
{
    LWLock      lock;
    int         trancheId;
} LoginGuardShmemState;

static HTAB    *loginGuardHash = NULL;
static LWLock  *loginGuardLock = NULL;

/* ---- GUCs ---- */
static bool guard_enabled = true;
static int  guard_max_attempts = 5;
static int  guard_window_seconds = 300;      /* 5 min, GUC_UNIT_S */
static int  guard_lockout_seconds = 900;     /* 15 min, GUC_UNIT_S */
static int  guard_max_tracked_roles = 1000;  /* PGC_POSTMASTER */

/* ---- previous hooks ---- */
static ClientAuthentication_hook_type prev_client_auth_hook = NULL;
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;
#if PG_VERSION_NUM >= 150000
static shmem_request_hook_type prev_shmem_request_hook = NULL;
#endif

void _PG_init(void);

static Size pg_login_guard_memsize(void);
static void pg_login_guard_shmem_request(void);
static void pg_login_guard_shmem_startup(void);
static void pg_login_guard_auth_check(Port *port, int status);
static void guard_copy_key(char *dst, const char *src);

PG_FUNCTION_INFO_V1(pg_login_guard_status);
PG_FUNCTION_INFO_V1(pg_login_guard_unlock);
PG_FUNCTION_INFO_V1(pg_login_guard_reset);

/*
 * _PG_init
 */
void
_PG_init(void)
{
    if (!process_shared_preload_libraries_in_progress)
        ereport(ERROR,
                (errmsg("pg_login_guard must be loaded via shared_preload_libraries"),
                 errhint("Add pg_login_guard to shared_preload_libraries in postgresql.conf and restart.")));

    DefineCustomBoolVariable("pg_login_guard.enabled",
                              "Enable failed-login tracking and lockout.",
                              NULL,
                              &guard_enabled,
                              true,
                              PGC_SIGHUP, 0,
                              NULL, NULL, NULL);

    DefineCustomIntVariable("pg_login_guard.max_attempts",
                             "Number of failed login attempts before a role is locked.",
                             NULL,
                             &guard_max_attempts,
                             5, 1, 1000,
                             PGC_SIGHUP, 0,
                             NULL, NULL, NULL);

    /*
     * Named "window_seconds", not "window": WINDOW is a reserved word in
     * PostgreSQL's SQL grammar, so a GUC named "pg_login_guard.window"
     * cannot be referenced bare in SHOW/SET/ALTER SYSTEM SET (all fail
     * with "syntax error at or near \"window\"") - only via
     * current_setting() or a fully double-quoted identifier.
     */
    DefineCustomIntVariable("pg_login_guard.window_seconds",
                             "Rolling time window in which failed attempts are counted.",
                             NULL,
                             &guard_window_seconds,
                             300, 1, INT_MAX,
                             PGC_SIGHUP, GUC_UNIT_S,
                             NULL, NULL, NULL);

    DefineCustomIntVariable("pg_login_guard.lockout_duration",
                             "How long a role stays locked once the attempt threshold is hit.",
                             NULL,
                             &guard_lockout_seconds,
                             900, 1, INT_MAX,
                             PGC_SIGHUP, GUC_UNIT_S,
                             NULL, NULL, NULL);

    DefineCustomIntVariable("pg_login_guard.max_tracked_roles",
                             "Maximum number of distinct roles tracked at once (sizes shared memory; requires restart).",
                             NULL,
                             &guard_max_tracked_roles,
                             1000, 10, 1000000,
                             PGC_POSTMASTER, 0,
                             NULL, NULL, NULL);

    MarkGUCPrefixReserved("pg_login_guard");

#if PG_VERSION_NUM >= 150000
    prev_shmem_request_hook = shmem_request_hook;
    shmem_request_hook = pg_login_guard_shmem_request;
#else
    /* On pre-15 there is no shmem_request_hook; request directly. */
    RequestAddinShmemSpace(pg_login_guard_memsize());
#endif

    prev_shmem_startup_hook = shmem_startup_hook;
    shmem_startup_hook = pg_login_guard_shmem_startup;

    prev_client_auth_hook = ClientAuthentication_hook;
    ClientAuthentication_hook = pg_login_guard_auth_check;
}

static Size
pg_login_guard_memsize(void)
{
    Size        size;

    size = MAXALIGN(sizeof(LoginGuardShmemState));
    size = add_size(size, hash_estimate_size(guard_max_tracked_roles, sizeof(LoginGuardEntry)));
    return size;
}

#if PG_VERSION_NUM >= 150000
static void
pg_login_guard_shmem_request(void)
{
    if (prev_shmem_request_hook)
        prev_shmem_request_hook();

    RequestAddinShmemSpace(pg_login_guard_memsize());
}
#endif

static void
pg_login_guard_shmem_startup(void)
{
    HASHCTL     info;
    bool        found;
    LoginGuardShmemState *state;

    if (prev_shmem_startup_hook)
        prev_shmem_startup_hook();

    loginGuardHash = NULL;

    LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);

    state = (LoginGuardShmemState *)
        ShmemInitStruct("pg_login_guard state", sizeof(LoginGuardShmemState), &found);
    if (!found)
    {
        state->trancheId = LWLockNewTrancheId();
        LWLockInitialize(&state->lock, state->trancheId);
    }
    LWLockRegisterTranche(state->trancheId, "pg_login_guard");
    loginGuardLock = &state->lock;

    memset(&info, 0, sizeof(info));
    info.keysize = NAMEDATALEN;
    info.entrysize = sizeof(LoginGuardEntry);

    loginGuardHash = ShmemInitHash("pg_login_guard hash",
                                    guard_max_tracked_roles,
                                    guard_max_tracked_roles,
                                    &info,
                                    HASH_ELEM | HASH_STRINGS);

    LWLockRelease(AddinShmemInitLock);
}

/* Copy a role name into a NAMEDATALEN buffer, guaranteed NUL-terminated. */
static void
guard_copy_key(char *dst, const char *src)
{
    memset(dst, 0, NAMEDATALEN);
    strncpy(dst, src, NAMEDATALEN - 1);
}

/*
 * pg_login_guard_auth_check
 *      ClientAuthentication_hook implementation.
 *
 * Called once per connection attempt, after Postgres has determined
 * whether the supplied credentials were valid (status == STATUS_OK)
 * or not (status == STATUS_ERROR), but before that result is acted on.
 * We can veto an otherwise-successful login by raising FATAL here.
 */
static void
pg_login_guard_auth_check(Port *port, int status)
{
    char        keyname[NAMEDATALEN];
    TimestampTz now;
    LoginGuardEntry *entry;
    bool        found;

    if (prev_client_auth_hook)
        prev_client_auth_hook(port, status);

    if (!guard_enabled || loginGuardHash == NULL)
        return;

    if (port->user_name == NULL || port->user_name[0] == '\0')
        return;

    guard_copy_key(keyname, port->user_name);
    now = GetCurrentTimestamp();

    LWLockAcquire(loginGuardLock, LW_EXCLUSIVE);

    entry = (LoginGuardEntry *) hash_search(loginGuardHash, keyname, HASH_FIND, &found);

    /* Still within an active lockout window? Reject regardless of status. */
    if (found && entry->locked_until != 0 && now < entry->locked_until)
    {
        TimestampTz until = entry->locked_until;

        LWLockRelease(loginGuardLock);

        ereport(FATAL,
                (errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
                 errmsg("role \"%s\" is temporarily locked due to repeated failed login attempts",
                        port->user_name),
                 errdetail("Locked until %s.", timestamptz_to_str(until)),
                 errhint("Wait for the lockout to expire, or ask an administrator to run pg_login_guard_unlock('%s').",
                          port->user_name)));
    }

    if (status == STATUS_OK)
    {
        /* Successful login clears any tracking history for this role. */
        if (found)
            (void) hash_search(loginGuardHash, keyname, HASH_REMOVE, NULL);
        LWLockRelease(loginGuardLock);
        return;
    }

    /* Failed login: record/advance the counter. */
    if (!found)
    {
        entry = (LoginGuardEntry *) hash_search(loginGuardHash, keyname, HASH_ENTER_NULL, &found);
        if (entry == NULL)
        {
            /* Table full; degrade gracefully rather than crash a backend. */
            LWLockRelease(loginGuardLock);
            ereport(WARNING,
                    (errmsg("pg_login_guard: tracking table is full, cannot record failed attempt for role \"%s\"",
                            port->user_name),
                     errhint("Increase pg_login_guard.max_tracked_roles and restart.")));
            return;
        }
        entry->attempt_count = 1;
        entry->window_started = now;
        entry->locked_until = 0;
    }
    else
    {
        long        secs;
        int         usecs;

        TimestampDifference(entry->window_started, now, &secs, &usecs);
        if (secs > guard_window_seconds)
        {
            /* Previous window expired; start a fresh one. */
            entry->attempt_count = 1;
            entry->window_started = now;
            entry->locked_until = 0;
        }
        else
        {
            entry->attempt_count++;
        }
    }

    if (entry->attempt_count >= guard_max_attempts)
    {
        entry->locked_until = now + (TimestampTz) guard_lockout_seconds * USECS_PER_SEC;

        ereport(LOG,
                (errmsg("pg_login_guard: role \"%s\" locked for %d seconds after %d failed login attempts within %d seconds",
                        port->user_name, guard_lockout_seconds,
                        entry->attempt_count, guard_window_seconds)));
    }

    LWLockRelease(loginGuardLock);
}

/*
 * pg_login_guard_status() - SQL-callable: dump current tracking table.
 */
Datum
pg_login_guard_status(PG_FUNCTION_ARGS)
{
    ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
    TupleDesc   tupdesc;
    Tuplestorestate *tupstore;
    MemoryContext oldcontext;
    MemoryContext per_query_ctx;
    HASH_SEQ_STATUS seq;
    LoginGuardEntry *entry;
    LoginGuardEntry *snapshot;
    int         cap;
    int         n = 0;
    int         i;

    if (loginGuardHash == NULL)
        ereport(ERROR,
                (errmsg("pg_login_guard is not active"),
                 errhint("Make sure pg_login_guard is listed in shared_preload_libraries.")));

    if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo) ||
        (rsinfo->allowedModes & SFRM_Materialize) == 0)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("set-valued function called in context that cannot accept a set")));

    rsinfo->returnMode = SFRM_Materialize;

    per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
    oldcontext = MemoryContextSwitchTo(per_query_ctx);

    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        elog(ERROR, "return type must be a row type");

    tupstore = tuplestore_begin_heap(true, false, work_mem);
    rsinfo->setResult = tupstore;
    rsinfo->setDesc = tupdesc;

    cap = guard_max_tracked_roles;
    snapshot = (LoginGuardEntry *) palloc(sizeof(LoginGuardEntry) * cap);

    LWLockAcquire(loginGuardLock, LW_SHARED);
    hash_seq_init(&seq, loginGuardHash);
    while (n < cap && (entry = (LoginGuardEntry *) hash_seq_search(&seq)) != NULL)
        snapshot[n++] = *entry;
    LWLockRelease(loginGuardLock);

    for (i = 0; i < n; i++)
    {
        Datum       values[4];
        bool        nulls[4];

        memset(nulls, 0, sizeof(nulls));
        values[0] = CStringGetTextDatum(snapshot[i].rolename);
        values[1] = Int32GetDatum(snapshot[i].attempt_count);
        values[2] = TimestampTzGetDatum(snapshot[i].window_started);
        if (snapshot[i].locked_until == 0)
            nulls[3] = true;
        else
            values[3] = TimestampTzGetDatum(snapshot[i].locked_until);

        tuplestore_putvalues(tupstore, tupdesc, values, nulls);
    }

    pfree(snapshot);
    MemoryContextSwitchTo(oldcontext);

    return (Datum) 0;
}

/*
 * pg_login_guard_unlock(role_name) - SQL-callable.
 */
Datum
pg_login_guard_unlock(PG_FUNCTION_ARGS)
{
    text       *arg = PG_GETARG_TEXT_PP(0);
    char        keyname[NAMEDATALEN];
    LoginGuardEntry *entry;
    bool        found;

    if (!superuser())
        ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                 errmsg("must be superuser to use pg_login_guard_unlock")));

    if (loginGuardHash == NULL)
        ereport(ERROR, (errmsg("pg_login_guard is not active")));

    guard_copy_key(keyname, text_to_cstring(arg));

    LWLockAcquire(loginGuardLock, LW_EXCLUSIVE);
    entry = (LoginGuardEntry *) hash_search(loginGuardHash, keyname, HASH_FIND, &found);
    if (found)
    {
        entry->attempt_count = 0;
        entry->locked_until = 0;
    }
    LWLockRelease(loginGuardLock);

    PG_RETURN_BOOL(found);
}

/*
 * pg_login_guard_reset(role_name) - SQL-callable.
 */
Datum
pg_login_guard_reset(PG_FUNCTION_ARGS)
{
    text       *arg = PG_GETARG_TEXT_PP(0);
    char        keyname[NAMEDATALEN];
    bool        found;

    if (!superuser())
        ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                 errmsg("must be superuser to use pg_login_guard_reset")));

    if (loginGuardHash == NULL)
        ereport(ERROR, (errmsg("pg_login_guard is not active")));

    guard_copy_key(keyname, text_to_cstring(arg));

    LWLockAcquire(loginGuardLock, LW_EXCLUSIVE);
    (void) hash_search(loginGuardHash, keyname, HASH_REMOVE, &found);
    LWLockRelease(loginGuardLock);

    PG_RETURN_BOOL(found);
}
