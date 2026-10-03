import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from db.extensions import Base
from services.whois_service import WhoisService
from services.advanced_monitor import AdvancedMonitorService
from model.host import Host
from model.whois_model import WhoisRecord

@pytest.fixture
def db_session():
    # Uses an in-memory SQLite engine for tests
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

def test_whois_service_mock(mocker, db_session):
    mock_whois = mocker.patch('whois.whois')
    mock_whois.return_value.registrar = "Test Registrar"
    mock_whois.return_value.creation_date = None
    mock_whois.return_value.expiration_date = None
    
    service = WhoisService(db_session)
    record = service.perform_whois('example.com')
    
    assert record.domain == 'example.com'
    assert record.registrar == "Test Registrar"
    
    # Verifies persistence
    saved_record = db_session.query(WhoisRecord).first()
    assert saved_record is not None
    assert saved_record.domain == 'example.com'

def test_whois_service_links_the_record_to_the_given_host(mocker, db_session):
    mock_whois = mocker.patch('whois.whois')
    mock_whois.return_value.registrar = "Test Registrar"
    mock_whois.return_value.creation_date = None
    mock_whois.return_value.expiration_date = None
    host = Host(nome='example.com', addr='example.com')
    db_session.add(host)
    db_session.commit()

    record = WhoisService(db_session).perform_whois('example.com', host_id=host.id)

    assert record.host_id == host.id


def test_advanced_monitor_service(mocker, db_session):
    # Mocks the connection utility so no real network scans happen
    mock_check = mocker.patch('services.advanced_monitor.check_host')
    # Simulating ports (name, addr, port, is_active)
    mock_check.side_effect = [
        ('TestServer', '127.0.0.1', 80, True),
        ('TestServer', '127.0.0.1', 443, False)
    ]

    service = AdvancedMonitorService(db_session)
    host = service.scan_ports('TestServer', '127.0.0.1', [80, 443], max_workers=1)

    # The mock runs for 80 and 443
    # Expect 80 to be active, 443 inactive based on side_effect
    assert '"80"' in host.ports_active or '80' in host.ports_active
    assert '"443"' in host.ports_inactive or '443' in host.ports_inactive
    
    saved_host = db_session.query(Host).first()
    assert saved_host is not None
    assert saved_host.nome == 'TestServer'
