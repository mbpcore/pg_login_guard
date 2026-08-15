MODULES = pg_login_guard
EXTENSION = pg_login_guard
DATA = sql/pg_login_guard--1.0.sql
PGFILEDESC = "pg_login_guard - lock roles after repeated failed login attempts"

REGRESS = pg_login_guard_admin
REGRESS_OPTS = --inputdir=test --outputdir=test

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
