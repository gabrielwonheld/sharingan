from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.extensions import Base
from model.host import Host
from model.subdomain_model import Subdomain
from phases.base import PhaseModule
from phases.recon.recon_phase import ReconPhase


class FakeSubfinder:
    names = ['www.example.com', 'api.example.com']

    @classmethod
    def find_subdomains(cls, domain):
        return list(cls.names)


def make_session():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_recon_phase_is_a_phase_module():
    assert issubclass(ReconPhase, PhaseModule)


def test_recon_phase_persists_subdomains_linked_to_the_host():
    session = make_session()
    phase = ReconPhase(session, subfinder=FakeSubfinder)

    host = phase.run(name='alvo', domain='example.com')

    names = {s.name for s in session.query(Subdomain).filter_by(host_id=host.id)}
    assert names == {'www.example.com', 'api.example.com'}


def test_recon_phase_reuses_the_host_scan_already_created():
    session = make_session()
    existing = Host(nome='alvo', addr='example.com')
    session.add(existing)
    session.commit()

    host = ReconPhase(session, subfinder=FakeSubfinder).run(name='alvo', domain='example.com')

    assert host.id == existing.id


def test_recon_phase_rerun_does_not_duplicate_known_subdomains_but_tracks_whats_new():
    session = make_session()
    phase = ReconPhase(session, subfinder=FakeSubfinder)
    phase.run(name='alvo', domain='example.com')
    assert phase.last_new_subdomains == ['api.example.com', 'www.example.com']

    class FakeSubfinderWithOneMore(FakeSubfinder):
        names = ['www.example.com', 'api.example.com', 'beta.example.com']

    phase2 = ReconPhase(session, subfinder=FakeSubfinderWithOneMore)
    host = phase2.run(name='alvo', domain='example.com')

    all_subdomains = session.query(Subdomain).filter_by(host_id=host.id).all()
    assert len(all_subdomains) == 3  # not duplicated
    assert phase2.last_new_subdomains == ['beta.example.com']
    assert phase2.last_all_subdomains == ['api.example.com', 'beta.example.com', 'www.example.com']


def test_recon_phase_reports_progress_with_the_subfinder_command():
    """Mirrors ScanPhase's on_progress: shows the actual command being run
    (subfinder -d <domain>), not just a generic "working..." message."""
    session = make_session()
    phase = ReconPhase(session, subfinder=FakeSubfinder)
    progress = []

    phase.run(name='alvo', domain='example.com', on_progress=progress.append)

    assert progress == ['Discovering subdomains (subfinder -d example.com)...']


def test_recon_phase_run_works_without_progress_callback():
    session = make_session()
    phase = ReconPhase(session, subfinder=FakeSubfinder)

    phase.run(name='alvo', domain='example.com')  # must not raise
