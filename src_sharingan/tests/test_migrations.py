from sqlalchemy import create_engine, inspect, text

from db.migrations import add_missing_columns, run_lightweight_migrations
# `Service.host = relationship('Host', ...)` referencia `Host` pelo nome — sem
# importar o módulo em algum lugar antes de usar o mapper, o SQLAlchemy não acha
# a classe no registro do declarative_base e explode com InvalidRequestError.
from model.host import Host  # noqa: F401


def make_legacy_engine():
    """Simula um `sharingan.db` criado antes da coluna `verification_status` existir."""
    engine = create_engine('sqlite:///:memory:')
    with engine.begin() as conn:
        conn.execute(text(
            """
            CREATE TABLE vulnerabilities (
                id INTEGER PRIMARY KEY,
                service_id INTEGER NOT NULL,
                cve VARCHAR(30) NOT NULL,
                cvss FLOAT,
                reference VARCHAR(255)
            )
            """
        ))
    return engine


def test_add_missing_columns_adds_columns_not_present():
    engine = make_legacy_engine()

    add_missing_columns(engine, 'vulnerabilities', {
        'verification_status': 'VARCHAR(20)',
        'verification_detail': 'VARCHAR(255)',
    })

    columns = {c['name'] for c in inspect(engine).get_columns('vulnerabilities')}
    assert 'verification_status' in columns
    assert 'verification_detail' in columns


def test_add_missing_columns_is_idempotent_and_does_not_duplicate():
    engine = make_legacy_engine()
    add_missing_columns(engine, 'vulnerabilities', {'verification_status': 'VARCHAR(20)'})

    # Rodar de novo (ex.: toda vez que o console abre) não pode dar erro tipo
    # "duplicate column name".
    add_missing_columns(engine, 'vulnerabilities', {'verification_status': 'VARCHAR(20)'})

    columns = [c['name'] for c in inspect(engine).get_columns('vulnerabilities')]
    assert columns.count('verification_status') == 1


def test_add_missing_columns_skips_table_that_does_not_exist_yet():
    engine = create_engine('sqlite:///:memory:')
    # Não deve levantar exceção — `create_all()` (chamado antes) ainda vai criar a
    # tabela do zero, já com as colunas certas.
    add_missing_columns(engine, 'vulnerabilities', {'verification_status': 'VARCHAR(20)'})


def make_legacy_services_engine():
    """Simula um `sharingan.db` criado antes da coluna `name` existir em `services`."""
    engine = create_engine('sqlite:///:memory:')
    with engine.begin() as conn:
        conn.execute(text(
            """
            CREATE TABLE services (
                id INTEGER PRIMARY KEY,
                host_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol VARCHAR(10),
                state VARCHAR(20),
                product VARCHAR(120),
                version VARCHAR(120),
                banner VARCHAR(255)
            )
            """
        ))
    return engine


def test_run_lightweight_migrations_adds_service_name_column_on_legacy_schema():
    from sqlalchemy.orm import sessionmaker

    from model.service_model import Service

    engine = make_legacy_services_engine()
    run_lightweight_migrations(engine)

    Session = sessionmaker(bind=engine)
    session = Session()
    # Without the migration, this INSERT via the ORM would break with
    # "table services has no column named name".
    session.add(Service(host_id=1, port=9200, name='wap-wsp'))
    session.commit()

    result = session.query(Service).first()
    assert result.name == 'wap-wsp'


def make_legacy_exploit_matches_engine():
    """Simulates a `sharingan.db` created before `cve_codes`/`verified` existed
    on `exploit_matches` (2026-09-17: added so exploit noise-reduction can
    cross-reference an exploit's own CVE against vulners' findings without
    re-invoking searchsploit)."""
    engine = create_engine('sqlite:///:memory:')
    with engine.begin() as conn:
        conn.execute(text(
            """
            CREATE TABLE exploit_matches (
                id INTEGER PRIMARY KEY,
                service_id INTEGER NOT NULL,
                title VARCHAR(255) NOT NULL,
                edb_id VARCHAR(20),
                path VARCHAR(255)
            )
            """
        ))
    return engine


def test_run_lightweight_migrations_adds_exploit_match_cve_columns_on_legacy_schema():
    from sqlalchemy.orm import sessionmaker

    from model.service_model import ExploitMatch

    engine = make_legacy_exploit_matches_engine()
    run_lightweight_migrations(engine)

    Session = sessionmaker(bind=engine)
    session = Session()
    # Without the migration, this INSERT via the ORM would break with
    # "table exploit_matches has no column named cve_codes".
    session.add(ExploitMatch(
        service_id=1, title='Redis - Example', edb_id='1',
        cve_codes='CVE-2018-12453', verified=True,
    ))
    session.commit()

    result = session.query(ExploitMatch).first()
    assert result.cve_codes == 'CVE-2018-12453'
    assert result.verified is True


def test_run_lightweight_migrations_adds_service_scan_run_id_on_legacy_schema():
    from sqlalchemy.orm import sessionmaker

    from model.service_model import Service

    engine = make_legacy_services_engine()
    run_lightweight_migrations(engine)

    session = sessionmaker(bind=engine)()
    session.add(Service(host_id=1, port=22))
    session.commit()

    assert session.query(Service).one().scan_run_id is None


def test_run_lightweight_migrations_drops_unique_constraint_on_hosts_nome():
    """`hosts.nome` used to be UNIQUE; SQLite can't drop a constraint with ALTER,
    so the migration rebuilds the table, keeping data and the UNIQUE on `addr`."""
    import pytest
    from sqlalchemy.exc import IntegrityError

    engine = create_engine('sqlite:///:memory:')
    with engine.begin() as conn:
        conn.execute(text(
            """
            CREATE TABLE hosts (
                id INTEGER NOT NULL,
                nome VARCHAR(80) NOT NULL,
                addr VARCHAR(120) NOT NULL,
                ports_active VARCHAR(120),
                ports_inactive VARCHAR(120),
                subdomains VARCHAR(120),
                PRIMARY KEY (id),
                UNIQUE (nome),
                UNIQUE (addr)
            )
            """
        ))
        conn.execute(text("INSERT INTO hosts (id, nome, addr, ports_active) VALUES (7, '16bits', '10.0.0.1', '[22]')"))

    run_lightweight_migrations(engine)
    run_lightweight_migrations(engine)  # idempotent

    with engine.begin() as conn:
        conn.execute(text("INSERT INTO hosts (nome, addr) VALUES ('16bits', '10.0.0.2')"))
        rows = conn.execute(text("SELECT id, nome, addr, ports_active FROM hosts ORDER BY id")).all()
    assert rows[0] == (7, '16bits', '10.0.0.1', '[22]')
    assert len(rows) == 2

    with pytest.raises(IntegrityError):
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO hosts (nome, addr) VALUES ('x', '10.0.0.1')"))


def test_run_lightweight_migrations_adds_whois_host_id_on_legacy_schema():
    engine = create_engine('sqlite:///:memory:')
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE whois_records (id INTEGER PRIMARY KEY, domain VARCHAR(255) NOT NULL, "
            "raw_data TEXT, registrar VARCHAR(255), creation_date DATETIME, "
            "expiration_date DATETIME, created_at DATETIME)"
        ))
        conn.execute(text("INSERT INTO whois_records (id, domain) VALUES (1, 'example.com')"))

    run_lightweight_migrations(engine)

    from sqlalchemy import inspect
    assert 'host_id' in {c['name'] for c in inspect(engine).get_columns('whois_records')}
    with engine.begin() as conn:
        assert conn.execute(text('SELECT host_id FROM whois_records')).scalar() is None


def make_pre_workspace_engine():
    """A `sharingan.db` from before workspaces: `hosts.addr` and
    `scope_rules.value` are globally UNIQUE and there's no `workspace_id`."""
    engine = create_engine('sqlite:///:memory:')
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE hosts (id INTEGER NOT NULL, nome VARCHAR(80) NOT NULL, "
            "addr VARCHAR(120) NOT NULL, ports_active VARCHAR(120), ports_inactive VARCHAR(120), "
            "subdomains VARCHAR(120), PRIMARY KEY (id), UNIQUE (addr))"
        ))
        conn.execute(text(
            "CREATE TABLE scope_rules (id INTEGER NOT NULL, kind VARCHAR(10) NOT NULL, "
            "value VARCHAR(255) NOT NULL, allow BOOLEAN NOT NULL, PRIMARY KEY (id), UNIQUE (value))"
        ))
        conn.execute(text("INSERT INTO hosts (id, nome, addr) VALUES (7, 'alvo', '10.0.0.1')"))
        conn.execute(text("INSERT INTO scope_rules (id, kind, value, allow) VALUES (3, 'domain', 'example.com', 1)"))
    return engine


def test_migration_moves_existing_hosts_and_scope_into_the_default_workspace():
    engine = make_pre_workspace_engine()

    run_lightweight_migrations(engine)

    with engine.begin() as conn:
        assert conn.execute(text('SELECT id, workspace_id, addr FROM hosts')).all() == [(7, 1, '10.0.0.1')]
        assert conn.execute(text('SELECT workspace_id, value FROM scope_rules')).all() == [(1, 'example.com')]


def test_migration_lets_the_same_address_exist_in_another_workspace():
    from sqlalchemy.exc import IntegrityError
    import pytest

    engine = make_pre_workspace_engine()
    run_lightweight_migrations(engine)

    with engine.begin() as conn:
        conn.execute(text("INSERT INTO hosts (nome, addr, workspace_id) VALUES ('b', '10.0.0.1', 2)"))
        conn.execute(text("INSERT INTO scope_rules (kind, value, allow, workspace_id) VALUES ('domain', 'example.com', 1, 2)"))
    with pytest.raises(IntegrityError):
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO hosts (nome, addr, workspace_id) VALUES ('c', '10.0.0.1', 2)"))


def test_migration_workspace_step_is_idempotent_and_creates_the_default_workspace():
    from model.host import Host  # noqa: F401  (register models)
    from model.scope_model import ScopeRule  # noqa: F401
    from model.workspace_model import Workspace
    from db.extensions import Base

    engine = make_pre_workspace_engine()
    Base.metadata.create_all(engine)  # creates `workspaces`, leaves the legacy tables alone

    run_lightweight_migrations(engine)
    run_lightweight_migrations(engine)

    with engine.begin() as conn:
        assert conn.execute(text('SELECT id, name FROM workspaces')).all() == [(1, 'default')]
        assert conn.execute(text('SELECT count(*) FROM hosts')).scalar() == 1


def test_migration_on_a_fresh_database_only_creates_the_default_workspace():
    from db.extensions import Base
    import model.host, model.scope_model, model.workspace_model  # noqa: F401,E401

    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)

    run_lightweight_migrations(engine)

    with engine.begin() as conn:
        assert conn.execute(text('SELECT id, name FROM workspaces')).all() == [(1, 'default')]
