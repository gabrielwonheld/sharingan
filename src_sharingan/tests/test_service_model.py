from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.extensions import Base
from model.host import Host
from model.service_model import ExploitMatch, ScanRun, Service, Vulnerability, current_services_filter


def make_session():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


def test_deleting_host_cascades_to_its_services():
    """Without cascade, deleting a Host would leave `Service` rows orphaned (host_id
    pointing to a record that no longer exists) — the console's `hosts -d` depends
    on this to actually clean up the data, not just the host."""
    session = make_session()
    host = Host(nome='alvo', addr='192.0.2.10')
    session.add(host)
    session.commit()
    session.add(Service(host_id=host.id, port=22, protocol='tcp', state='open'))
    session.add(Service(host_id=host.id, port=80, protocol='tcp', state='open'))
    session.commit()
    assert session.query(Service).count() == 2

    session.delete(host)
    session.commit()

    assert session.query(Service).count() == 0


def test_deleting_service_cascades_to_its_vulnerabilities_and_exploit_matches():
    session = make_session()
    host = Host(nome='alvo', addr='192.0.2.11')
    session.add(host)
    session.commit()
    service = Service(host_id=host.id, port=22, protocol='tcp', state='open')
    session.add(service)
    session.commit()
    session.add(Vulnerability(service_id=service.id, cve='CVE-2024-0001', cvss=9.0))
    session.add(ExploitMatch(service_id=service.id, title='Exploit X', edb_id='1'))
    session.commit()
    assert session.query(Vulnerability).count() == 1
    assert session.query(ExploitMatch).count() == 1

    session.delete(service)
    session.commit()

    assert session.query(Vulnerability).count() == 0
    assert session.query(ExploitMatch).count() == 0


def test_deleting_host_cascades_all_the_way_to_vulnerabilities_and_exploits():
    session = make_session()
    host = Host(nome='alvo', addr='192.0.2.12')
    session.add(host)
    session.commit()
    service = Service(host_id=host.id, port=22, protocol='tcp', state='open')
    session.add(service)
    session.commit()
    session.add(Vulnerability(service_id=service.id, cve='CVE-2024-0002', cvss=7.5))
    session.add(ExploitMatch(service_id=service.id, title='Exploit Y', edb_id='2'))
    session.commit()

    session.delete(host)
    session.commit()

    assert session.query(Service).count() == 0
    assert session.query(Vulnerability).count() == 0
    assert session.query(ExploitMatch).count() == 0


def test_scan_run_groups_the_services_found_in_that_execution():
    session = make_session()
    host = Host(nome='alvo', addr='192.0.2.20')
    session.add(host)
    session.commit()
    run = ScanRun(host_id=host.id)
    session.add(run)
    session.commit()
    session.add(Service(host_id=host.id, scan_run_id=run.id, port=22))
    session.add(Service(host_id=host.id, scan_run_id=run.id, port=80))
    session.commit()

    assert sorted(s.port for s in run.services) == [22, 80]
    assert run.host is host
    assert run.services[0].scan_run is run


def test_scan_run_defaults_to_running_status_with_a_start_timestamp():
    session = make_session()
    host = Host(nome='alvo', addr='192.0.2.21')
    session.add(host)
    session.commit()
    run = ScanRun(host_id=host.id)
    session.add(run)
    session.commit()

    assert run.status == 'running'
    assert run.started_at is not None
    assert run.finished_at is None


def test_host_keeps_every_scan_run_as_history():
    session = make_session()
    host = Host(nome='alvo', addr='192.0.2.22')
    session.add(host)
    session.commit()
    session.add(ScanRun(host_id=host.id))
    session.add(ScanRun(host_id=host.id))
    session.commit()

    assert len(host.scan_runs) == 2


def test_deleting_scan_run_cascades_to_its_services_but_keeps_other_runs():
    session = make_session()
    host = Host(nome='alvo', addr='192.0.2.23')
    session.add(host)
    session.commit()
    old_run = ScanRun(host_id=host.id)
    new_run = ScanRun(host_id=host.id)
    session.add_all([old_run, new_run])
    session.commit()
    old_service = Service(host_id=host.id, scan_run_id=old_run.id, port=22)
    new_service = Service(host_id=host.id, scan_run_id=new_run.id, port=22)
    session.add_all([old_service, new_service])
    session.commit()
    session.add(Vulnerability(service_id=old_service.id, cve='CVE-2024-0003', cvss=8.0))
    session.commit()

    session.delete(old_run)
    session.commit()

    assert session.query(ScanRun).count() == 1
    assert [s.scan_run_id for s in session.query(Service).all()] == [new_run.id]
    assert session.query(Vulnerability).count() == 0


def test_deleting_host_cascades_to_its_scan_runs():
    session = make_session()
    host = Host(nome='alvo', addr='192.0.2.24')
    session.add(host)
    session.commit()
    run = ScanRun(host_id=host.id)
    session.add(run)
    session.commit()
    session.add(Service(host_id=host.id, scan_run_id=run.id, port=22))
    session.commit()

    session.delete(host)
    session.commit()

    assert session.query(ScanRun).count() == 0
    assert session.query(Service).count() == 0


def test_service_without_scan_run_is_still_valid_for_legacy_rows():
    """Existing databases have Service rows from before ScanRun existed."""
    session = make_session()
    host = Host(nome='alvo', addr='192.0.2.25')
    session.add(host)
    session.commit()
    session.add(Service(host_id=host.id, port=22))
    session.commit()

    assert session.query(Service).one().scan_run_id is None


def _current_ports(session, host):
    return sorted(
        s.port for s in session.query(Service).filter(Service.host_id == host.id, current_services_filter())
    )


def test_current_services_filter_keeps_legacy_services_when_host_has_no_runs():
    session = make_session()
    host = Host(nome='alvo', addr='192.0.2.30')
    session.add(host)
    session.commit()
    session.add(Service(host_id=host.id, port=22))
    session.commit()

    assert _current_ports(session, host) == [22]


def test_current_services_filter_returns_only_the_latest_run_of_each_host():
    session = make_session()
    host = Host(nome='alvo', addr='192.0.2.31')
    other = Host(nome='outro', addr='192.0.2.32')
    session.add_all([host, other])
    session.commit()
    old_run = ScanRun(host_id=host.id, status='ok')
    session.add(old_run)
    session.commit()
    new_run = ScanRun(host_id=host.id, status='ok')
    other_run = ScanRun(host_id=other.id, status='ok')
    session.add_all([new_run, other_run])
    session.commit()
    session.add_all([
        Service(host_id=host.id, scan_run_id=old_run.id, port=22),
        Service(host_id=host.id, scan_run_id=new_run.id, port=80),
        Service(host_id=host.id, port=21),  # legacy row, superseded by the runs
        Service(host_id=other.id, scan_run_id=other_run.id, port=443),
    ])
    session.commit()

    assert _current_ports(session, host) == [80]
    assert _current_ports(session, other) == [443]


def test_current_services_filter_ignores_failed_runs():
    """A scan that blew up midway must not hide the host's last good result."""
    session = make_session()
    host = Host(nome='alvo', addr='192.0.2.33')
    session.add(host)
    session.commit()
    good = ScanRun(host_id=host.id, status='ok')
    session.add(good)
    session.commit()
    failed = ScanRun(host_id=host.id, status='failed')
    session.add(failed)
    session.commit()
    session.add(Service(host_id=host.id, scan_run_id=good.id, port=22))
    session.commit()

    assert _current_ports(session, host) == [22]
