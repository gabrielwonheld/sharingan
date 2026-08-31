from sqlalchemy import inspect, text


def add_missing_columns(engine, table_name: str, columns: dict) -> None:
    """Adiciona colunas que faltam numa tabela já existente no banco.

    O projeto usa `Base.metadata.create_all()` (sem Alembic/migração de verdade),
    que só cria tabelas que ainda não existem — nunca altera uma tabela já
    existente para adicionar uma coluna nova. Sem isso, um `sharingan.db` criado
    antes de um model ganhar uma coluna nova quebraria com
    `OperationalError: no such column` na primeira query que tocar nela.

    `columns` é um dict `{nome: definição SQL}`, ex.:
    `{'verification_status': 'VARCHAR(20)'}`. Idempotente — rodar de novo não
    duplica nem falha.
    """
    inspector = inspect(engine)
    if table_name not in inspector.get_table_names():
        # `create_all()` (chamado logo antes, em `init_db()`) ainda vai criar essa
        # tabela do zero, já com as colunas certas — nada a fazer aqui.
        return

    existing = {col['name'] for col in inspector.get_columns(table_name)}
    with engine.begin() as conn:
        for name, definition in columns.items():
            if name not in existing:
                conn.execute(text(f'ALTER TABLE {table_name} ADD COLUMN {name} {definition}'))


def run_lightweight_migrations(engine) -> None:
    """Ponto único chamado por `init_db()` logo após `create_all()`.

    Registre aqui qualquer coluna nova adicionada a um model que já existe em
    bancos de usuários reais — isso só sabe *adicionar* coluna (nunca renomear
    ou remover), então é seguro rodar em todo boot.
    """
    add_missing_columns(engine, 'vulnerabilities', {
        'verification_status': 'VARCHAR(20)',
        'verification_detail': 'VARCHAR(255)',
    })
    # `Service.name` (2026-08-31): nmap's own guessed service name, persisted even
    # when product/version stay unknown — see model/service_model.py.
    add_missing_columns(engine, 'services', {
        'name': 'VARCHAR(120)',
    })
