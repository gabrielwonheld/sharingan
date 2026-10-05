import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from db.extensions import Base
from model.host import Host
from model.scope_model import ScopeRule
from model.service_model import Service
from model.workspace_model import DEFAULT_WORKSPACE_ID, Workspace


def make_session():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_default_workspace_id_is_one():
    assert DEFAULT_WORKSPACE_ID == 1


def test_workspace_names_are_unique():
    session = make_session()
    session.add(Workspace(name='cliente-a'))
    session.commit()
    session.add(Workspace(name='cliente-a'))

    with pytest.raises(IntegrityError):
        session.commit()


def test_a_host_defaults_to_the_default_workspace():
    session = make_session()
    host = Host(nome='alvo', addr='10.0.0.1')
    session.add(host)
    session.commit()

    assert host.workspace_id == DEFAULT_WORKSPACE_ID


def test_the_same_address_can_exist_once_per_workspace():
    session = make_session()
    session.add_all([Workspace(id=1, name='default'), Workspace(id=2, name='b')])
    session.add_all([
        Host(nome='x', addr='10.0.0.1', workspace_id=1),
        Host(nome='y', addr='10.0.0.1', workspace_id=2),
    ])
    session.commit()

    assert session.query(Host).count() == 2


def test_the_same_address_twice_in_one_workspace_is_rejected():
    session = make_session()
    session.add_all([Host(nome='x', addr='10.0.0.1', workspace_id=2),
                     Host(nome='y', addr='10.0.0.1', workspace_id=2)])

    with pytest.raises(IntegrityError):
        session.commit()


def test_the_same_scope_value_can_exist_once_per_workspace():
    session = make_session()
    session.add_all([
        ScopeRule(kind='domain', value='example.com', workspace_id=1),
        ScopeRule(kind='domain', value='example.com', workspace_id=2),
    ])
    session.commit()
    session.add(ScopeRule(kind='domain', value='example.com', workspace_id=2))

    with pytest.raises(IntegrityError):
        session.commit()


def test_deleting_a_workspace_deletes_its_hosts_scope_and_everything_below():
    session = make_session()
    workspace = Workspace(id=2, name='b')
    session.add(workspace)
    session.commit()
    host = Host(nome='x', addr='10.0.0.1', workspace_id=2)
    session.add_all([host, ScopeRule(kind='ip', value='10.0.0.1', workspace_id=2)])
    session.commit()
    session.add(Service(host_id=host.id, port=22, protocol='tcp', state='open'))
    session.commit()

    session.delete(workspace)
    session.commit()

    assert session.query(Host).count() == 0
    assert session.query(ScopeRule).count() == 0
    assert session.query(Service).count() == 0
