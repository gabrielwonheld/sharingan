from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.extensions import Base
from model.finding_model import Finding
from model.host import Host
from phases.base import PhaseModule
from phases.fuzz.fuzz_phase import FuzzPhase
from phases.fuzz.tools.gobuster_tool import FuzzMatch


class FakeGobuster:
    matches = [
        FuzzMatch(path='/admin', status_code=301, size=169, redirect='http://example.com/admin/'),
        FuzzMatch(path='/index.html', status_code=200, size=1234, redirect=None),
    ]

    @classmethod
    def enumerate(cls, url, wordlist, **kwargs):
        return list(cls.matches)


def make_session():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_fuzz_phase_is_a_phase_module():
    assert issubclass(FuzzPhase, PhaseModule)


def test_fuzz_phase_persists_findings_linked_to_the_host():
    session = make_session()
    phase = FuzzPhase(session, gobuster=FakeGobuster)

    host = phase.run(name='alvo', url='http://example.com', wordlist='/tmp/words.txt')

    paths = {f.path for f in session.query(Finding).filter_by(host_id=host.id)}
    assert paths == {'/admin', '/index.html'}
    admin = session.query(Finding).filter_by(path='/admin').one()
    assert admin.status_code == 301 and admin.size == 169
    assert admin.redirect == 'http://example.com/admin/'


def test_fuzz_phase_derives_the_host_from_the_url_hostname():
    session = make_session()

    host = FuzzPhase(session, gobuster=FakeGobuster).run(
        name='alvo', url='http://example.com:8080/base', wordlist='/tmp/words.txt',
    )

    assert host.addr == 'example.com'


def test_fuzz_phase_rerun_does_not_duplicate_but_tracks_whats_new():
    session = make_session()
    phase = FuzzPhase(session, gobuster=FakeGobuster)
    phase.run(name='alvo', url='http://example.com', wordlist='/tmp/words.txt')
    assert sorted(phase.last_new_paths) == ['/admin', '/index.html']

    class FakeGobusterWithOneMore(FakeGobuster):
        matches = FakeGobuster.matches + [FuzzMatch(path='/secret', status_code=200, size=1, redirect=None)]

    phase2 = FuzzPhase(session, gobuster=FakeGobusterWithOneMore)
    host = phase2.run(name='alvo', url='http://example.com', wordlist='/tmp/words.txt')

    findings = session.query(Finding).filter_by(host_id=host.id).all()
    assert len(findings) == 3  # not duplicated
    assert phase2.last_new_paths == ['/secret']
    assert len(phase2.last_all_matches) == 3


def test_fuzz_phase_reports_progress_with_the_gobuster_command():
    session = make_session()
    phase = FuzzPhase(session, gobuster=FakeGobuster)
    progress = []

    phase.run(name='alvo', url='http://example.com', wordlist='/tmp/words.txt', on_progress=progress.append)

    assert progress == ['Enumerating directories/files (gobuster dir -u http://example.com)...']


def test_fuzz_phase_passes_options_through_to_gobuster():
    received = {}

    class RecordingGobuster:
        @classmethod
        def enumerate(cls, url, wordlist, **kwargs):
            received.update(kwargs)
            return []

    session = make_session()
    FuzzPhase(session, gobuster=RecordingGobuster).run(
        name='alvo', url='http://example.com', wordlist='/tmp/words.txt',
        extensions='php,bak', threads=50, status_codes='200,301',
    )

    assert received == {'extensions': 'php,bak', 'threads': 50, 'status_codes': '200,301'}
