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
