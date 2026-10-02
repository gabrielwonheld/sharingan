from pathlib import Path
from unittest.mock import patch


def test_default_database_url_is_independent_of_the_current_working_directory(monkeypatch, tmp_path):
    """Real bug found in use (2026-09-17): the default `DATABASE_URL` was the
    relative string 'sqlite:///sharingan.db', resolved by SQLite against the
    process's current working directory. Launching the console from
    `src_sharingan/` (e.g. `uv run sharingan_repl.py`) versus from the repo root
    (`uv run python src_sharingan/sharingan_repl.py`) silently pointed at two
    *different* `sharingan.db` files. That ambiguity is what led to a live
    console session's `sharingan.db` being mistaken for a stray file and
    overwritten out from under its open connection — the direct cause of a
    "sqlite3.OperationalError: attempt to write a readonly database" during a
    `scan`. The default must resolve to the same absolute path no matter which
    directory the process was started from."""
    import db.database as database

    monkeypatch.delenv('DATABASE_URL', raising=False)

    monkeypatch.chdir(tmp_path)
    url_from_elsewhere = database._default_database_url()

    monkeypatch.chdir(Path(database.__file__).resolve().parent)
    url_from_package_dir = database._default_database_url()

    assert url_from_elsewhere == url_from_package_dir
    assert url_from_elsewhere.startswith('sqlite:///')
    resolved_path = Path(url_from_elsewhere.removeprefix('sqlite:///'))
    assert resolved_path.is_absolute()
    assert resolved_path.name == 'sharingan.db'


def test_init_db_runs_lightweight_migrations_after_create_all():
    """Real gap found while adding `Service.name` (2026-08-31): `db/migrations.py`
    exists and is fully tested in isolation (`test_migrations.py`), but `init_db()`
    never actually called it — `Base.metadata.create_all()` only creates tables that
    don't exist yet, it never alters an existing one. Without this wiring, a
    pre-existing `sharingan.db` (like the one the user already has, from before this
    fix) would never gain the new `services.name` column and the very next `scan`
    would crash with `OperationalError: no such column: services.name` the first
    time the ORM tried to insert into it."""
    import db.database as database
    from db.extensions import Base

    with patch.object(Base.metadata, 'create_all') as mock_create_all, \
         patch('db.migrations.run_lightweight_migrations') as mock_migrate:
        database.init_db()

    mock_create_all.assert_called_once_with(bind=database.engine)
    mock_migrate.assert_called_once_with(database.engine)
