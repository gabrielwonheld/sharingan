from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.report import build_workspace_report
from db.extensions import Base
from model.crawl_model import CrawledPage, HarvestedEmail
from model.finding_model import Finding
from model.host import Host
from model.scope_model import ScopeRule
from model.service_model import ExploitMatch, ScanRun, Service, Vulnerability
from model.subdomain_model import Subdomain
from model.whois_model import WhoisRecord
from model.workspace_model import Workspace

NOW = datetime(2026, 10, 5, 12, 30, tzinfo=timezone.utc)


def make_session():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add_all([Workspace(id=1, name='default'), Workspace(id=2, name='cliente-a')])
    session.commit()
    return session


def report(session, workspace_id=1, name='default'):
    return build_workspace_report(session, workspace_id, name, now=NOW)


def seed_full_host(session, workspace_id=1, addr='example.com'):
    host = Host(nome='alvo', addr=addr, workspace_id=workspace_id)
    session.add(host)
    session.commit()
    session.add(WhoisRecord(
        domain=addr, host_id=host.id, registrar='Test Registrar',
        creation_date=datetime(2000, 1, 1), expiration_date=datetime(2030, 1, 1),
    ))
    session.add_all([Subdomain(host_id=host.id, name=f'{n}.{addr}') for n in ('www', 'api')])
    old, new = ScanRun(host_id=host.id, status='ok'), ScanRun(host_id=host.id, status='ok')
    session.add_all([old, new])
    session.commit()
    session.add(Service(host_id=host.id, scan_run_id=old.id, port=21, protocol='tcp', state='open', product='OldFTP'))
    ssh = Service(host_id=host.id, scan_run_id=new.id, port=22, protocol='tcp', state='open',
                  product='OpenSSH', version='9.6')
    session.add(ssh)
    session.commit()
    session.add_all([
        Vulnerability(service_id=ssh.id, cve='CVE-2024-0001', cvss=5.0, reference='https://vulners.com/a'),
        Vulnerability(service_id=ssh.id, cve='CVE-2024-6387', cvss=8.1),
        ExploitMatch(service_id=ssh.id, title='OpenSSH regreSSHion', edb_id='52269',
                     cve_codes='CVE-2024-6387', verified=True),
        CrawledPage(host_id=host.id, url=f'http://{addr}/', status_code=200, depth=0),
        HarvestedEmail(host_id=host.id, email=f'admin@{addr}', source_url=f'http://{addr}/'),
        Finding(host_id=host.id, url=f'http://{addr}', path='/admin', status_code=200, size=10),
    ])
    session.commit()
    return host


def test_header_names_the_workspace_with_generation_time_and_host_count():
    session = make_session()
    seed_full_host(session)

    text = report(session)

    assert text.startswith('# Sharingan report: default')
    assert 'Generated: 2026-10-05 12:30 UTC' in text
    assert 'Hosts: 1' in text


def test_scope_section_lists_rules_or_says_there_is_none():
    session = make_session()
    assert 'No scope defined' in report(session)

    session.add_all([ScopeRule(kind='domain', value='example.com', allow=True),
                     ScopeRule(kind='domain', value='admin.example.com', allow=False)])
    session.commit()
    text = report(session)

    assert '| include | domain | example.com |' in text
    assert '| exclude | domain | admin.example.com |' in text


def test_summary_has_one_row_per_host_with_counts():
    session = make_session()
    seed_full_host(session)

    text = report(session)

    assert '| example.com | alvo | 1 | 2 | 1 | 2 | 1 | 1 | 1 |' in text


def test_host_section_has_every_phase_that_has_data():
    session = make_session()
    seed_full_host(session)

    text = report(session)

    for heading in ('## example.com (alvo)', '### WHOIS', '### Subdomains', '### Services',
                    '### Vulnerabilities', '### Exploits', '### Scan history',
                    '### Crawled pages', '### Emails', '### Directory findings'):
        assert heading in text
    assert 'Test Registrar' in text
    assert 'api.example.com' in text and 'www.example.com' in text
    assert '| 22 | open | OpenSSH 9.6 | 2 | 1 |' in text
    assert '/admin' in text and 'admin@example.com' in text


def test_services_are_only_the_latest_scan_and_vulns_are_sorted_by_cvss():
    session = make_session()
    seed_full_host(session)

    text = report(session)

    assert 'OldFTP' not in text
    assert text.index('CVE-2024-6387') < text.index('CVE-2024-0001')
    assert 'https://vulners.com/a' in text


def test_exploits_show_title_edb_id_verified_and_cves():
    session = make_session()
    seed_full_host(session)

    text = report(session)

    assert '| 22 | OpenSSH 9.6 | OpenSSH regreSSHion | 52269 | yes | CVE-2024-6387 |' in text


def test_scan_history_lists_every_run():
    session = make_session()
    seed_full_host(session)

    text = report(session)

    history = text.split('### Scan history')[1].split('###')[0]
    assert history.count('| ok |') == 2


def test_sections_without_data_are_left_out():
    session = make_session()
    session.add(Host(nome='alvo', addr='10.0.0.1', workspace_id=1))
    session.commit()

    text = report(session)

    assert '## 10.0.0.1 (alvo)' in text
    assert 'No results have been collected for this host yet' in text
    for heading in ('### WHOIS', '### Services', '### Emails', '### Directory findings'):
        assert heading not in text


def test_only_the_requested_workspace_is_included():
    session = make_session()
    seed_full_host(session, workspace_id=1, addr='mine.example.com')
    seed_full_host(session, workspace_id=2, addr='theirs.example.com')
    session.add(ScopeRule(kind='domain', value='theirs.example.com', workspace_id=2))
    session.commit()

    text = report(session, workspace_id=1, name='default')

    assert 'mine.example.com' in text
    assert 'theirs.example.com' not in text


def test_an_empty_workspace_still_produces_a_report():
    session = make_session()

    text = report(session, workspace_id=2, name='cliente-a')

    assert text.startswith('# Sharingan report: cliente-a')
    assert 'Hosts: 0' in text
    assert 'No hosts in this workspace yet' in text


def test_untrusted_text_cannot_break_tables_or_inject_html():
    session = make_session()
    host = Host(nome='alvo', addr='10.0.0.1', workspace_id=1)
    session.add(host)
    session.commit()
    run = ScanRun(host_id=host.id, status='ok')
    session.add(run)
    session.commit()
    session.add(Service(host_id=host.id, scan_run_id=run.id, port=80, protocol='tcp', state='open',
                        product='evil|pipe\nnewline <script>alert(1)</script>'))
    session.commit()

    text = report(session)

    assert '<script>' not in text
    assert '&lt;script&gt;' in text
    assert 'evil\\|pipe newline' in text
