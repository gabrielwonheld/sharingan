"""Every phase attaches its host to the workspace it was built for."""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.extensions import Base
from model.host import Host
from model.whois_model import WhoisRecord
from phases.fuzz.fuzz_phase import FuzzPhase
from phases.recon.recon_phase import ReconPhase
from phases.recon.whois_phase import WhoisPhase
from phases.web.spider_phase import SpiderPhase
from phases.web.tools.crawler import CrawlResult


def make_session():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


class FakeSubfinder:
    @staticmethod
    def find_subdomains(domain):
        return []


class FakeGobuster:
    @staticmethod
    def enumerate(*args, **kwargs):
        return []


class FakeCrawler:
    @staticmethod
    def crawl(**kwargs):
        return CrawlResult()


class FakeWhois:
    def __init__(self, session):
        self.session = session

    def perform_whois(self, domain, host_id=None):
        record = WhoisRecord(domain=domain, host_id=host_id)
        self.session.add(record)
        self.session.commit()
        return record


def _host(session):
    return session.query(Host).one()


def test_recon_phase_uses_its_workspace():
    session = make_session()
    ReconPhase(session, subfinder=FakeSubfinder, workspace_id=2).run(name='a', domain='example.com')
    assert _host(session).workspace_id == 2


def test_fuzz_phase_uses_its_workspace():
    session = make_session()
    FuzzPhase(session, gobuster=FakeGobuster, workspace_id=2).run(
        name='a', url='http://example.com', wordlist='w.txt')
    assert _host(session).workspace_id == 2


def test_spider_phase_uses_its_workspace():
    session = make_session()
    SpiderPhase(session, crawler=FakeCrawler, workspace_id=2).run(
        name='a', url='http://example.com/', max_depth=1, max_pages=1, delay=0, user_agent='UA')
    assert _host(session).workspace_id == 2


def test_whois_phase_uses_its_workspace():
    session = make_session()
    WhoisPhase(session, whois_service=FakeWhois, workspace_id=2).run(domain='example.com')
    assert _host(session).workspace_id == 2


def test_scan_phase_uses_its_workspace():
    from phases.scan.scan_phase import ScanPhase

    class NoPorts:
        @staticmethod
        def scan_ports(*args, **kwargs):
            return []

        @staticmethod
        def is_available():
            return True

    session = make_session()
    phase = ScanPhase(session, rustscan=NoPorts, workspace_id=2)
    phase.run(name='a', target='10.0.0.1')
    assert _host(session).workspace_id == 2


def test_the_same_target_in_two_workspaces_makes_two_hosts():
    session = make_session()
    ReconPhase(session, subfinder=FakeSubfinder, workspace_id=1).run(name='a', domain='example.com')
    ReconPhase(session, subfinder=FakeSubfinder, workspace_id=2).run(name='a', domain='example.com')
    assert session.query(Host).count() == 2
