MODULES = pg_login_guard
EXTENSION = pg_login_guard
DATA = sql/pg_login_guard--1.0.sql
# NOTE: intentionally not setting PGFILEDESC. On PGXS (out-of-tree) builds
# it triggers a win32ver.rc version-resource step that only auto-generates
# inside the full PostgreSQL source tree; PGXS extensions must ship their
# own win32ver.rc to use it. Not worth the complexity for cosmetic DLL
# metadata, so it's left unset.

REGRESS = pg_login_guard_admin
REGRESS_OPTS = --inputdir=test --outputdir=test

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
