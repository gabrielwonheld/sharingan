from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.extensions import Base
from model.host import Host
from model.whois_model import WhoisRecord
from phases.base import PhaseModule
from phases.recon.whois_phase import WhoisPhase


class FakeWhoisService:
    calls = []

    def __init__(self, session):
        self.session = session

    def perform_whois(self, domain, host_id=None):
        FakeWhoisService.calls.append((domain, host_id))
        record = WhoisRecord(domain=domain, registrar='Fake Registrar', host_id=host_id)
        self.session.add(record)
        self.session.commit()
        return record


def make_session():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_whois_phase_is_a_phase_module():
    assert issubclass(WhoisPhase, PhaseModule)


def test_whois_phase_links_the_record_to_the_host_of_that_domain():
    FakeWhoisService.calls = []
    session = make_session()

    record = WhoisPhase(session, whois_service=FakeWhoisService).run(domain='example.com')

    host = session.query(Host).filter_by(addr='example.com').one()
    assert record.host_id == host.id
    assert FakeWhoisService.calls == [('example.com', host.id)]


def test_whois_phase_reuses_the_host_recon_or_scan_already_created():
    session = make_session()
    existing = Host(nome='alvo', addr='example.com')
    session.add(existing)
    session.commit()

    record = WhoisPhase(session, whois_service=FakeWhoisService).run(domain='example.com')

    assert record.host_id == existing.id
    assert session.query(Host).count() == 1


def test_whois_phase_reports_the_lookup_as_progress():
    session = make_session()
    progress = []

    WhoisPhase(session, whois_service=FakeWhoisService).run(
        domain='example.com', on_progress=progress.append
    )

    assert progress == ['Querying WHOIS for example.com...']


def test_deleting_the_host_cascades_to_its_whois_records():
    session = make_session()
    WhoisPhase(session, whois_service=FakeWhoisService).run(domain='example.com')

    session.delete(session.query(Host).one())
    session.commit()

    assert session.query(WhoisRecord).count() == 0
