from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.extensions import Base
from model.host import Host
from phases.common import get_or_create_host


def make_session():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_get_or_create_host_creates_a_new_host():
    session = make_session()

    host = get_or_create_host(session, 'alvo', '192.0.2.1')

    assert host.id is not None
    assert host.nome == 'alvo'
    assert host.addr == '192.0.2.1'


def test_get_or_create_host_reuses_the_existing_host_by_address():
    session = make_session()
    first = get_or_create_host(session, 'alvo', '192.0.2.1')

    second = get_or_create_host(session, 'outro-nome', '192.0.2.1')

    assert second.id == first.id
    assert session.query(Host).count() == 1


def test_get_or_create_host_is_scoped_to_the_workspace():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from db.extensions import Base
    from phases.common import get_or_create_host

    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()

    in_default = get_or_create_host(session, 'a', '10.0.0.1')
    in_other = get_or_create_host(session, 'a', '10.0.0.1', workspace_id=2)
    again_other = get_or_create_host(session, 'zzz', '10.0.0.1', workspace_id=2)

    assert in_default.id != in_other.id
    assert (in_default.workspace_id, in_other.workspace_id) == (1, 2)
    assert again_other.id == in_other.id
