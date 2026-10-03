import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def _default_database_url() -> str:
    # An absolute path anchored to this package's own directory (src_sharingan/),
    # not the relative "sqlite:///sharingan.db" this used to be: a relative path
    # is resolved against the process's current working directory, so the exact
    # same command run from a different directory (e.g. `sharingan_repl.py` from
    # inside src_sharingan/ vs. from the repo root) silently opens a *different*
    # sharingan.db file. Anchoring it here makes the default the same file no
    # matter where the process was started from.
    project_root = Path(__file__).resolve().parent.parent
    return f"sqlite:///{project_root / 'sharingan.db'}"


# Reads from the environment, falling back to local SQLite so it always works
DATABASE_URL = os.environ.get("DATABASE_URL", _default_database_url())

engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    from db.extensions import Base
    # Make sure the models are imported before create_all()
    from model.host import Host
    from model.whois_model import WhoisRecord
    from model.scope_model import ScopeRule
    from model.service_model import ScanRun, Service, Vulnerability, ExploitMatch
    from model.subdomain_model import Subdomain
    from model.finding_model import Finding
    from db.migrations import run_lightweight_migrations
    Base.metadata.create_all(bind=engine)
    # `create_all()` only creates tables that don't exist yet — it never alters an
    # existing one to add a column a model gained later. Without this, a
    # `sharingan.db` created before a model change would keep erroring with
    # "no such column" on the first query that touches it.
    run_lightweight_migrations(engine)

def get_session():
    return SessionLocal()
