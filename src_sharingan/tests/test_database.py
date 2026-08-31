from unittest.mock import patch


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
