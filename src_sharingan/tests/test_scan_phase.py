import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.extensions import Base
from model.host import Host
from model.service_model import ExploitMatch, ScanRun, Service, Vulnerability, current_services_filter
from phases.base import PhaseModule
from phases.scan.scan_phase import ScanPhase
from phases.scan.tools.nmap_tool import ServiceFingerprint
from phases.scan.tools.vulners_tool import VulnerabilityMatch


class FakeRustscan:
    @classmethod
    def scan_ports(cls, target, **kwargs):
        return [22, 80]


class FakeNmap:
    @classmethod
    def fingerprint(cls, target, ports, xml_output_path, extra_args=None):
        return [
            ServiceFingerprint(22, 'tcp', 'open', 'OpenSSH', '8.9p1', 'OpenSSH 8.9p1'),
            ServiceFingerprint(80, 'tcp', 'open', 'nginx', '1.18.0', 'nginx 1.18.0'),
        ]


class FakeNmapWithGuessedNameOnly:
    """Simulates nmap -sV failing to grab a banner (no product/version) but still
    reporting its port-table guess at the service name — the real-world case
    (e.g. Elasticsearch/Kibana on non-default ports) that used to end up as a
    bare '?' in the console because `ScanPhase` never persisted `fingerprint.name`."""

    @classmethod
    def fingerprint(cls, target, ports, xml_output_path, extra_args=None):
        return [
            ServiceFingerprint(9200, 'tcp', 'open', None, None, None, 'wap-wsp'),
        ]


class FakeSearchsploit:
    """Only 'OpenSSH' has a match — lets tests prove exploits land on the
    *correct* service (the port 22 OpenSSH one, not nginx on port 80) instead
    of always the host's first service."""

    @classmethod
    def is_available(cls):
        return True

    @classmethod
    def search_product(cls, product):
        if product == 'OpenSSH':
            return [
                {'Title': 'OpenSSH 8.9p1 - Example Exploit', 'EDB-ID': '12345', 'Path': '/path/exploit.py'},
            ]
        return []


class UnavailableSearchsploit:
    @classmethod
    def is_available(cls):
        return False

    @classmethod
    def search_product(cls, product):
        raise AssertionError('should not be called when unavailable')


class FakeVulnersUnavailable:
    """Default in tests that aren't about vulners — preserves the previous
    behavior (searchsploit runs unconditionally, if it's itself available)."""

    @classmethod
    def is_available(cls):
        return False

    @classmethod
    def build_nmap_args(cls, min_cvss):
        raise AssertionError('should not be called when unavailable')

    @classmethod
    def parse_xml(cls, xml_path):
        raise AssertionError('should not be called when unavailable')


class FakeVulnersWithFindings:
    @classmethod
    def is_available(cls):
        return True

    @classmethod
    def build_nmap_args(cls, min_cvss):
        return ['--script', 'vulners', '--script-args', f'mincvss={min_cvss}']

    @classmethod
    def parse_xml(cls, xml_path):
        return [VulnerabilityMatch(port=22, cve='CVE-2023-9999', cvss=9.8, reference='https://vulners.com/cve/CVE-2023-9999')]


class FakeVulnersNoFindings:
    @classmethod
    def is_available(cls):
        return True

    @classmethod
    def build_nmap_args(cls, min_cvss):
        return ['--script', 'vulners', '--script-args', f'mincvss={min_cvss}']

    @classmethod
    def parse_xml(cls, xml_path):
        return []


class EmptyRustscan:
    @classmethod
    def scan_ports(cls, target, **kwargs):
        return []


class ExplodingNmap:
    @classmethod
    def fingerprint(cls, *args, **kwargs):
        raise AssertionError('nmap should not be called without open ports')


def make_session():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


def make_phase(session, **overrides):
    kwargs = dict(
        rustscan=FakeRustscan,
        nmap=FakeNmap,
        vulners=FakeVulnersUnavailable,
        searchsploit=FakeSearchsploit,
    )
    kwargs.update(overrides)
    return ScanPhase(session, **kwargs)


def test_scan_phase_searches_only_the_first_word_of_a_multi_word_product():
    """Real bug found during manual verification (2026-09-17) against a live
    target: nmap's own `product` field is often a multi-word descriptive
    string ("Redis key-value store", "PostgreSQL DB"), not just the short
    name exploit-db titles use. Confirmed empirically that `searchsploit -t`
    requires *every* word supplied to appear (whole-word, not substring) —
    `searchsploit -t "Redis key-value store"` returns 0 results even though
    `searchsploit -t redis` finds the 5 real matches; same story for
    "PostgreSQL DB" (0) vs "PostgreSQL" (13). `ScanPhase` must search only the
    product's first word."""
    session = make_session()

    received_terms = []

    class RecordingSearchsploit:
        @classmethod
        def is_available(cls):
            return True

        @classmethod
        def search_product(cls, product):
            received_terms.append(product)
            return []

    class NmapWithMultiWordProduct:
        @classmethod
        def fingerprint(cls, target, ports, xml_output_path, extra_args=None):
            return [
                ServiceFingerprint(6379, 'tcp', 'open', 'Redis key-value store', '5.0.7', 'Redis key-value store 5.0.7'),
            ]

    phase = make_phase(session, nmap=NmapWithMultiWordProduct, searchsploit=RecordingSearchsploit)
    phase.run(name='alvo', target='192.0.2.12')

    assert received_terms == ['Redis']


def test_scan_phase_does_not_search_exploits_for_a_service_nmap_could_not_identify():
    """Real bug found during manual verification (2026-09-17) against a live
    target: a port nmap can't fingerprint at all gets `<service name="unknown">`
    in the XML — literally the string "unknown", not a real product name.
    Searching `searchsploit -t unknown` matched completely unrelated exploits
    (LibTIFF, a Windows COM privilege escalation, a Firefox/Safari one) for a
    port that turned out to just be a local VS Code process. "unknown" must
    be treated the same as no identification at all — skip the search."""
    session = make_session()

    received_terms = []

    class RecordingSearchsploit:
        @classmethod
        def is_available(cls):
            return True

        @classmethod
        def search_product(cls, product):
            received_terms.append(product)
            return []

    class NmapWithUnidentifiedService:
        @classmethod
        def fingerprint(cls, target, ports, xml_output_path, extra_args=None):
            return [
                ServiceFingerprint(16501, 'tcp', 'open', None, None, None, 'unknown'),
            ]

    phase = make_phase(session, nmap=NmapWithUnidentifiedService, searchsploit=RecordingSearchsploit)
    phase.run(name='alvo', target='192.0.2.13')

    assert received_terms == []


def test_scan_phase_is_a_phase_module():
    assert issubclass(ScanPhase, PhaseModule)
    session = make_session()
    phase = make_phase(session)
    assert phase.name == 'scan'


def test_scan_phase_persists_services_and_exploit_matches():
    session = make_session()
    phase = make_phase(session)

    host = phase.run(name='alvo-teste', target='192.0.2.10')

    assert host.id is not None

    services = session.query(Service).filter_by(host_id=host.id).all()
    assert {s.port for s in services} == {22, 80}

    ssh_service = next(s for s in services if s.port == 22)
    assert ssh_service.product == 'OpenSSH'
    assert ssh_service.version == '8.9p1'

    matches = session.query(ExploitMatch).all()
    assert len(matches) == 1
    assert matches[0].edb_id == '12345'


def test_scan_phase_attributes_exploit_matches_to_the_correct_service():
    """Real bug fixed (pending item #7 in CLAUDE.md): exploit matches used to
    always be attached to the host's *first* `Service`, regardless of which
    product they actually matched — `searchsploit --nmap` gave no reliable
    way to know which port a hit came from. Now `ScanPhase` searches
    per-service (`SearchsploitTool.search_product`, once per fingerprinted
    product), so each match is written against its own service. Here only
    'OpenSSH' (port 22) has a match; nginx (port 80) must end up with none —
    not "the host's first service" (which nginx isn't, but proves the
    association is real rather than incidentally correct)."""
    session = make_session()
    phase = make_phase(session)

    host = phase.run(name='alvo-teste', target='192.0.2.11')

    ssh_service = session.query(Service).filter_by(host_id=host.id, port=22).one()
    nginx_service = session.query(Service).filter_by(host_id=host.id, port=80).one()

    assert len(ssh_service.exploit_matches) == 1
    assert ssh_service.exploit_matches[0].edb_id == '12345'
    assert nginx_service.exploit_matches == []


def test_scan_phase_persists_guessed_service_name_when_product_is_unknown():
    """The console's 'Service' column fell back to only `product`/`version`, so a
    port nmap couldn't fingerprint a banner for showed nothing but '?' even when
    nmap's own port-table guess (`fingerprint.name`) was available. `ScanPhase`
    must persist that guess too so the console has something to fall back to."""
    session = make_session()
    phase = make_phase(session, nmap=FakeNmapWithGuessedNameOnly, searchsploit=UnavailableSearchsploit)

    host = phase.run(name='alvo-guess', target='192.0.2.110')

    service = session.query(Service).filter_by(host_id=host.id).one()
    assert service.product is None
    assert service.name == 'wap-wsp'


def _current_services(session, host):
    return session.query(Service).filter(Service.host_id == host.id, current_services_filter()).all()


def test_scan_phase_creates_a_finished_scan_run_with_its_services():
    session = make_session()
    phase = make_phase(session)

    host = phase.run(name='alvo', target='192.0.2.99')

    run = session.query(ScanRun).filter_by(host_id=host.id).one()
    assert run.status == 'ok'
    assert run.started_at is not None and run.finished_at is not None
    assert {s.scan_run_id for s in session.query(Service).filter_by(host_id=host.id)} == {run.id}
    assert phase.last_scan_run.id == run.id


def test_scan_phase_rescan_keeps_history_but_current_view_shows_only_the_latest_run():
    """Real bug in use: re-running `scan` stacked duplicate rows. Now each run is
    kept as history, and the "current" view is just the newest run."""
    session = make_session()
    phase = make_phase(session, vulners=FakeVulnersWithFindings)

    host1 = phase.run(name='alvo', target='192.0.2.100')
    host2 = phase.run(name='alvo', target='192.0.2.100')

    assert host1.id == host2.id  # same host, doesn't duplicate the Host either
    assert session.query(ScanRun).filter_by(host_id=host2.id).count() == 2
    assert session.query(Service).filter_by(host_id=host2.id).count() == 4  # history kept

    current = _current_services(session, host2)
    assert {s.port for s in current} == {22, 80}
    assert len(current) == 2
    # vulnerabilities/exploits belong to the run that found them: one each in the
    # latest run, none leaking across runs onto the same service
    assert sum(len(s.vulnerabilities) for s in current) == 1
    assert sum(len(s.exploit_matches) for s in current) == 1


def test_scan_phase_rescan_with_no_open_ports_makes_the_current_view_empty():
    """If the host no longer shows any open port on a re-scan, that's its current
    state — the previous run stays as history, but is no longer "current"."""
    session = make_session()
    phase = make_phase(session)

    phase.run(name='alvo', target='192.0.2.101')
    assert session.query(Service).count() == 2

    phase2 = make_phase(session, rustscan=EmptyRustscan, nmap=ExplodingNmap)
    host = phase2.run(name='alvo', target='192.0.2.101')

    assert host.ports_active == '[]'
    assert _current_services(session, host) == []
    assert session.query(ScanRun).filter_by(host_id=host.id).count() == 2
    assert phase2.last_scan_run.status == 'ok'


def test_scan_phase_marks_run_failed_and_keeps_previous_result_current_when_a_step_blows_up():
    session = make_session()
    make_phase(session).run(name='alvo', target='192.0.2.102')

    class BrokenNmap:
        @classmethod
        def fingerprint(cls, *args, **kwargs):
            raise RuntimeError('nmap exploded')

    phase = make_phase(session, nmap=BrokenNmap)
    with pytest.raises(RuntimeError):
        phase.run(name='alvo', target='192.0.2.102')

    host = session.query(Host).filter_by(addr='192.0.2.102').one()
    assert phase.last_scan_run.status == 'failed'
    assert phase.last_scan_run.finished_at is not None
    assert {s.port for s in _current_services(session, host)} == {22, 80}


def test_scan_phase_with_no_open_ports_does_not_call_nmap():
    session = make_session()
    phase = make_phase(session, rustscan=EmptyRustscan, nmap=ExplodingNmap)

    host = phase.run(name='sem-portas', target='192.0.2.20')

    assert host.ports_active == '[]'
    assert session.query(Service).filter_by(host_id=host.id).count() == 0


def test_scan_phase_skips_searchsploit_when_unavailable():
    session = make_session()
    phase = make_phase(session, searchsploit=UnavailableSearchsploit)

    host = phase.run(name='sem-searchsploit', target='192.0.2.30')

    assert session.query(Service).filter_by(host_id=host.id).count() == 2
    assert session.query(ExploitMatch).count() == 0


def test_scan_phase_persists_vulnerabilities_and_runs_searchsploit_when_relevant():
    """vulners found something (high CVSS) -> persists Vulnerability AND still runs searchsploit."""
    session = make_session()
    phase = make_phase(session, vulners=FakeVulnersWithFindings)

    host = phase.run(name='alvo-vulneravel', target='192.0.2.40')

    vulns = session.query(Vulnerability).all()
    assert len(vulns) == 1
    assert vulns[0].cve == 'CVE-2023-9999'
    assert vulns[0].cvss == 9.8

    ssh_service = session.query(Service).filter_by(host_id=host.id, port=22).one()
    assert vulns[0].service_id == ssh_service.id

    # relevant enough to also run searchsploit
    assert session.query(ExploitMatch).count() == 1


def test_scan_phase_skips_searchsploit_when_vulners_finds_nothing():
    """vulners available but with no findings (nothing >= mincvss) -> not worth running searchsploit."""
    session = make_session()

    class SearchsploitThatShouldNotRun:
        @classmethod
        def is_available(cls):
            return True

        @classmethod
        def search_product(cls, product):
            raise AssertionError('should not run when vulners found nothing relevant')

    phase = make_phase(session, vulners=FakeVulnersNoFindings, searchsploit=SearchsploitThatShouldNotRun)

    host = phase.run(name='alvo-sem-vulnerabilidade', target='192.0.2.50')

    assert session.query(Vulnerability).count() == 0
    assert session.query(Service).filter_by(host_id=host.id).count() == 2


def test_scan_phase_records_last_run_flags_when_vulners_unavailable():
    """The console needs to know, after `run()`, whether each step actually ran —
    without this there's no way to tell 'ran and found nothing' apart from 'didn't run at all'."""
    session = make_session()
    phase = make_phase(session)  # vulners=FakeVulnersUnavailable, searchsploit=FakeSearchsploit (available)

    phase.run(name='alvo', target='192.0.2.70')

    assert phase.last_vulners_enabled is False
    assert phase.last_searchsploit_ran is True


def test_scan_phase_records_last_run_flags_when_vulners_finds_something_relevant():
    session = make_session()
    phase = make_phase(session, vulners=FakeVulnersWithFindings)

    phase.run(name='alvo', target='192.0.2.71')

    assert phase.last_vulners_enabled is True
    assert phase.last_searchsploit_ran is True


def test_scan_phase_records_last_run_flags_when_vulners_finds_nothing_relevant():
    session = make_session()

    class SearchsploitThatShouldNotRun:
        @classmethod
        def is_available(cls):
            return True

        @classmethod
        def search_product(cls, product):
            raise AssertionError('should not run when vulners found nothing relevant')

    phase = make_phase(session, vulners=FakeVulnersNoFindings, searchsploit=SearchsploitThatShouldNotRun)

    phase.run(name='alvo', target='192.0.2.72')

    assert phase.last_vulners_enabled is True
    assert phase.last_searchsploit_ran is False


def test_scan_phase_survives_searchsploit_runtime_failure():
    """Reproduces the real error seen by the user: `searchsploit` in PATH (found
    'available') but failing at runtime (in the real case, missing `xmllint`)
    used to take down the whole scan with a `CalledProcessError`, losing even the
    nmap fingerprint that had already been persisted. `searchsploit` is an
    optional/best-effort step — a failure in it can't take down the rest of the scan."""
    import subprocess

    session = make_session()

    class FailingSearchsploit:
        @classmethod
        def is_available(cls):
            return True

        @classmethod
        def search_product(cls, product):
            raise subprocess.CalledProcessError(1, ['searchsploit', '-t', product, '-j'])

    phase = make_phase(session, searchsploit=FailingSearchsploit)

    host = phase.run(name='alvo', target='192.0.2.80')

    # the nmap fingerprint stays persisted even with searchsploit failing
    assert session.query(Service).filter_by(host_id=host.id).count() == 2
    assert session.query(ExploitMatch).count() == 0
    assert phase.last_searchsploit_ran is False
    assert phase.last_searchsploit_error is not None


def test_scan_phase_reports_progress_for_each_step():
    """The user asked for step-by-step progress feedback (rustscan -> nmap -> searchsploit)
    instead of a single static message — `run()` accepts an optional `on_progress`
    callback called with a description right before each actual subprocess."""
    session = make_session()
    phase = make_phase(session)  # vulners=FakeVulnersUnavailable, searchsploit=FakeSearchsploit
    progress = []

    phase.run(name='alvo', target='192.0.2.90', on_progress=progress.append)

    assert progress == [
        'Scanning open ports (rustscan)...',
        'Fingerprinting services and versions (nmap -sV)...',
        'Looking up matching exploits (searchsploit)...',
    ]


def test_scan_phase_progress_mentions_vulners_when_embedded_in_nmap():
    session = make_session()
    phase = make_phase(session, vulners=FakeVulnersWithFindings)
    progress = []

    phase.run(name='alvo', target='192.0.2.91', on_progress=progress.append)

    nmap_step = next(step for step in progress if 'nmap' in step.lower())
    assert 'vulners' in nmap_step.lower()


def test_scan_phase_progress_omits_searchsploit_step_when_not_attempted():
    """If searchsploit isn't even going to run (skipped by design, or unavailable),
    it doesn't make sense to announce a step that isn't going to happen."""
    session = make_session()

    class SearchsploitThatShouldNotRun:
        @classmethod
        def is_available(cls):
            return True

        @classmethod
        def search_product(cls, product):
            raise AssertionError('should not run when vulners found nothing relevant')

    phase = make_phase(session, vulners=FakeVulnersNoFindings, searchsploit=SearchsploitThatShouldNotRun)
    progress = []

    phase.run(name='alvo', target='192.0.2.92', on_progress=progress.append)

    assert not any('searchsploit' in step.lower() for step in progress)


def test_scan_phase_progress_stops_after_no_open_ports():
    session = make_session()
    phase = make_phase(session, rustscan=EmptyRustscan, nmap=ExplodingNmap)
    progress = []

    phase.run(name='alvo', target='192.0.2.93', on_progress=progress.append)

    assert progress == ['Scanning open ports (rustscan)...']


def test_scan_phase_run_works_without_progress_callback():
    """`on_progress` is optional — calling `run()` without it (the old behavior) must not break."""
    session = make_session()
    phase = make_phase(session)

    host = phase.run(name='alvo', target='192.0.2.94')

    assert host.id is not None


def test_scan_phase_passes_vulners_args_into_nmap_when_available():
    session = make_session()

    received = {}

    class RecordingNmap:
        @classmethod
        def fingerprint(cls, target, ports, xml_output_path, extra_args=None):
            received['extra_args'] = extra_args
            return [ServiceFingerprint(22, 'tcp', 'open', 'OpenSSH', '8.9p1', 'OpenSSH 8.9p1')]

    phase = make_phase(session, nmap=RecordingNmap, vulners=FakeVulnersNoFindings)
    phase.run(name='alvo', target='192.0.2.60')

    assert received['extra_args'] == ['--script', 'vulners', '--script-args', 'mincvss=7.0']


def test_scan_phase_allows_the_same_name_for_different_addresses():
    """Real bug in use: `hosts.nome` was UNIQUE, so `scan 16bits <domain>` followed
    by `scan 16bits 127.0.0.1` failed with an IntegrityError. The address
    identifies a host; the name is just a label."""
    session = make_session()
    phase = make_phase(session)

    host1 = phase.run(name='16bits', target='erp.16bits.net.br')
    host2 = phase.run(name='16bits', target='127.0.0.1')

    assert host1.id != host2.id
    assert session.query(Host).filter_by(nome='16bits').count() == 2


def test_scan_phase_passes_rustscan_options_to_the_tool():
    received = {}

    class RecordingRustscan:
        @classmethod
        def scan_ports(cls, target, **kwargs):
            received.update(kwargs)
            return []

    session = make_session()
    phase = make_phase(session, rustscan=RecordingRustscan, rustscan_batch=200, rustscan_timeout=9000)

    phase.run(name='alvo', target='192.0.2.150')

    assert received == {'batch_size': 200, 'timeout_ms': 9000}
