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


def test_run_lightweight_migrations_lets_orm_use_new_columns_on_legacy_schema():
    from sqlalchemy.orm import sessionmaker

    from model.service_model import Vulnerability

    engine = make_legacy_engine()
    run_lightweight_migrations(engine)

    Session = sessionmaker(bind=engine)
    session = Session()
    # Sem a migração, esse INSERT via ORM quebraria com
    # "table vulnerabilities has no column named verification_status".
    session.add(Vulnerability(service_id=1, cve='CVE-2024-0001', verification_status='patched'))
    session.commit()

    result = session.query(Vulnerability).first()
    assert result.verification_status == 'patched'
