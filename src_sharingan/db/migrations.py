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


def drop_unique_constraint_on_hosts_nome(engine) -> None:
    """Removes the legacy `UNIQUE (nome)` from `hosts` (2026-10-02).

    SQLite can't drop a constraint with ALTER TABLE, so the table is rebuilt
    (create new -> copy rows -> drop old -> rename), keeping `UNIQUE (addr)`.
    Does nothing when `hosts` doesn't exist yet or has no unique index on `nome`
    (so it's idempotent and safe to run on every boot).
    """
    inspector = inspect(engine)
    if 'hosts' not in inspector.get_table_names():
        return
    has_unique_nome = any(
        constraint['column_names'] == ['nome']
        for constraint in inspector.get_unique_constraints('hosts')
    ) or any(
        index.get('unique') and index['column_names'] == ['nome']
        for index in inspector.get_indexes('hosts')
    )
    if not has_unique_nome:
        return

    with engine.begin() as conn:
        conn.execute(text(
            """
            CREATE TABLE hosts_new (
                id INTEGER NOT NULL,
                nome VARCHAR(80) NOT NULL,
                addr VARCHAR(120) NOT NULL,
                ports_active VARCHAR(120),
                ports_inactive VARCHAR(120),
                subdomains VARCHAR(120),
                PRIMARY KEY (id),
                UNIQUE (addr)
            )
            """
        ))
        conn.execute(text(
            'INSERT INTO hosts_new (id, nome, addr, ports_active, ports_inactive, subdomains) '
            'SELECT id, nome, addr, ports_active, ports_inactive, subdomains FROM hosts'
        ))
        conn.execute(text('DROP TABLE hosts'))
        conn.execute(text('ALTER TABLE hosts_new RENAME TO hosts'))


def _columns(engine, table_name: str) -> set:
    return {col['name'] for col in inspect(engine).get_columns(table_name)}


def add_workspaces(engine) -> None:
    """Workspaces (2026-10-05): creates the default workspace (id 1) and moves
    pre-existing hosts and scope rules into it.

    `hosts.addr` and `scope_rules.value` used to be globally UNIQUE; they must
    now be unique *per workspace*. SQLite can't alter a constraint, so each
    table is rebuilt (create new -> copy rows into workspace 1 -> drop old ->
    rename). Idempotent: a table that already has `workspace_id` is left alone.
    """
    tables = inspect(engine).get_table_names()

    if 'workspaces' in tables:
        with engine.begin() as conn:
            conn.execute(text(
                "INSERT INTO workspaces (id, name, created_at) "
                "SELECT 1, 'default', CURRENT_TIMESTAMP "
                "WHERE NOT EXISTS (SELECT 1 FROM workspaces WHERE id = 1)"
            ))

    if 'hosts' in tables and 'workspace_id' not in _columns(engine, 'hosts'):
        with engine.begin() as conn:
            conn.execute(text(
                """
                CREATE TABLE hosts_new (
                    id INTEGER NOT NULL,
                    workspace_id INTEGER NOT NULL DEFAULT 1,
                    nome VARCHAR(80) NOT NULL,
                    addr VARCHAR(120) NOT NULL,
                    ports_active VARCHAR(120),
                    ports_inactive VARCHAR(120),
                    subdomains VARCHAR(120),
                    PRIMARY KEY (id),
                    CONSTRAINT uq_host_workspace_addr UNIQUE (workspace_id, addr),
                    FOREIGN KEY(workspace_id) REFERENCES workspaces (id)
                )
                """
            ))
            conn.execute(text(
                'INSERT INTO hosts_new (id, workspace_id, nome, addr, ports_active, ports_inactive, subdomains) '
                'SELECT id, 1, nome, addr, ports_active, ports_inactive, subdomains FROM hosts'
            ))
            conn.execute(text('DROP TABLE hosts'))
            conn.execute(text('ALTER TABLE hosts_new RENAME TO hosts'))

    if 'scope_rules' in tables and 'workspace_id' not in _columns(engine, 'scope_rules'):
        with engine.begin() as conn:
            conn.execute(text(
                """
                CREATE TABLE scope_rules_new (
                    id INTEGER NOT NULL,
                    workspace_id INTEGER NOT NULL DEFAULT 1,
                    kind VARCHAR(10) NOT NULL,
                    value VARCHAR(255) NOT NULL,
                    allow BOOLEAN NOT NULL,
                    PRIMARY KEY (id),
                    CONSTRAINT uq_scope_workspace_value UNIQUE (workspace_id, value),
                    FOREIGN KEY(workspace_id) REFERENCES workspaces (id)
                )
                """
            ))
            conn.execute(text(
                'INSERT INTO scope_rules_new (id, workspace_id, kind, value, allow) '
                'SELECT id, 1, kind, value, allow FROM scope_rules'
            ))
            conn.execute(text('DROP TABLE scope_rules'))
            conn.execute(text('ALTER TABLE scope_rules_new RENAME TO scope_rules'))


def run_lightweight_migrations(engine) -> None:
    """Ponto único chamado por `init_db()` logo após `create_all()`.

    Registre aqui qualquer coluna nova adicionada a um model que já existe em
    bancos de usuários reais — isso só sabe *adicionar* coluna (nunca renomear
    ou remover), então é seguro rodar em todo boot.
    """
    drop_unique_constraint_on_hosts_nome(engine)
    add_workspaces(engine)
    # `Service.name` (2026-08-31): nmap's own guessed service name, persisted even
    # when product/version stay unknown — see model/service_model.py.
    # `Service.scan_run_id` (2026-10-02): links a service to the ScanRun that
    # found it. Left NULL for pre-existing rows (legacy data, no run).
    add_missing_columns(engine, 'services', {
        'name': 'VARCHAR(120)',
        'scan_run_id': 'INTEGER REFERENCES scan_runs(id)',
    })
    # `ExploitMatch.cve_codes`/`verified` (2026-09-17): exploit-db's own CVE
    # tags and verification flag, used to cross-reference/rank exploit
    # results instead of showing every text-matched hit undifferentiated —
    # see model/service_model.py.
    add_missing_columns(engine, 'exploit_matches', {
        'cve_codes': 'VARCHAR(255)',
        'verified': 'BOOLEAN',
    })
    # `WhoisRecord.host_id` (2026-10-03): `whois` now runs through the Recon
    # phase and links each record to the Host of the domain. NULL for old rows.
    add_missing_columns(engine, 'whois_records', {
        'host_id': 'INTEGER REFERENCES hosts(id)',
    })
