import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Reads from the environment, falling back to local SQLite so it always works
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///sharingan.db")

engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    from db.extensions import Base
    # Make sure the models are imported before create_all()
    from model.host import Host
    from model.whois_model import WhoisRecord
    from model.service_model import Service, Vulnerability, ExploitMatch
    from db.migrations import run_lightweight_migrations
    Base.metadata.create_all(bind=engine)
    # `create_all()` only creates tables that don't exist yet — it never alters an
    # existing one to add a column a model gained later. Without this, a
    # `sharingan.db` created before a model change would keep erroring with
    # "no such column" on the first query that touches it.
    run_lightweight_migrations(engine)

def get_session():
    return SessionLocal()
