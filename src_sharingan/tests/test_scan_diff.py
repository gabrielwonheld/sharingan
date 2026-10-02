from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.extensions import Base
from model.host import Host
from model.service_model import ScanRun, Service, Vulnerability
from phases.scan.scan_diff import diff_scan_runs


def make_session():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def make_run(session, host, services, vulns=()):
    """services: [(port, product, version)], vulns: [(port, cve)]."""
    run = ScanRun(host_id=host.id, status='ok')
    session.add(run)
    session.commit()
    by_port = {}
    for port, product, version in services:
        service = Service(host_id=host.id, scan_run_id=run.id, port=port, protocol='tcp',
                          state='open', product=product, version=version)
        session.add(service)
        session.commit()
        by_port[port] = service
    for port, cve in vulns:
        session.add(Vulnerability(service_id=by_port[port].id, cve=cve, cvss=8.0))
    session.commit()
    return run


def make_host(session):
    host = Host(nome='alvo', addr='192.0.2.60')
    session.add(host)
    session.commit()
    return host


def test_diff_reports_opened_and_closed_ports():
    session = make_session()
    host = make_host(session)
    old = make_run(session, host, [(22, 'OpenSSH', '9.6'), (80, 'nginx', '1.24')])
    new = make_run(session, host, [(22, 'OpenSSH', '9.6'), (443, 'nginx', '1.24')])

    diff = diff_scan_runs(session, old, new)

    assert diff.opened == [443]
    assert diff.closed == [80]
    assert diff.version_changed == []


def test_diff_reports_version_changes_with_old_and_new_label():
    session = make_session()
    host = make_host(session)
    old = make_run(session, host, [(22, 'OpenSSH', '8.9')])
    new = make_run(session, host, [(22, 'OpenSSH', '9.6')])

    diff = diff_scan_runs(session, old, new)

    assert diff.version_changed == [(22, 'OpenSSH 8.9', 'OpenSSH 9.6')]


def test_diff_reports_new_and_resolved_cves_per_port():
    session = make_session()
    host = make_host(session)
    old = make_run(session, host, [(22, 'OpenSSH', '8.9')], vulns=[(22, 'CVE-2024-0001'), (22, 'CVE-2024-0002')])
    new = make_run(session, host, [(22, 'OpenSSH', '8.9')], vulns=[(22, 'CVE-2024-0002'), (22, 'CVE-2024-0003')])

    diff = diff_scan_runs(session, old, new)

    assert diff.new_cves == [(22, 'CVE-2024-0003')]
    assert diff.resolved_cves == [(22, 'CVE-2024-0001')]


def test_diff_of_identical_runs_is_empty():
    session = make_session()
    host = make_host(session)
    old = make_run(session, host, [(22, 'OpenSSH', '9.6')], vulns=[(22, 'CVE-2024-0001')])
    new = make_run(session, host, [(22, 'OpenSSH', '9.6')], vulns=[(22, 'CVE-2024-0001')])

    assert diff_scan_runs(session, old, new).is_empty
