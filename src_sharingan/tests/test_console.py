from types import SimpleNamespace
from unittest.mock import MagicMock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.context import SessionContext
from db.extensions import Base
from model.host import Host
from model.scope_model import ScopeRule
from model.service_model import ExploitMatch, Service, Vulnerability
from view.console import InteractiveConsole


def make_console(session):
    # Avoids the real __init__ (which would open a real PromptSession/DB) and
    # injects only what the handlers use.
    console = InteractiveConsole.__new__(InteractiveConsole)
    console.console = MagicMock()
    console.session_db = session
    console.context = SessionContext()
    return console


def make_session():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


def test_command_whois_parses_domain_correctly(mocker):
    """Before the fix, `command_whois` read `args[1]` — with `whois example.com`
    (args = ['example.com']) that raised an IndexError. Now it goes through
    WhoisPhase, like `recon` goes through ReconPhase."""
    session = make_session()
    console = make_console(session)

    fake_record = SimpleNamespace(registrar='Test Registrar', creation_date=None, expiration_date=None)
    mock_phase_cls = mocker.patch('view.console.WhoisPhase')
    mock_phase_cls.return_value.run.return_value = fake_record

    console.command_whois(['example.com'])

    mock_phase_cls.return_value.run.assert_called_once_with(
        domain='example.com', on_progress=console._report_progress
    )
    assert _table_cell_values(console.console.print, 'WHOIS Result: example.com', 'Value')[0] == 'Test Registrar'


def test_command_whois_requires_a_domain():
    console = make_console(make_session())

    console.command_whois([])

    assert any('Usage: whois' in str(c.args[0]) for c in console.console.print.call_args_list)


def test_command_whois_blocked_when_out_of_scope(mocker):
    console = make_console(make_session())
    console.command_scope(['add', 'example.com'])
    mock_phase_cls = mocker.patch('view.console.WhoisPhase')

    console.command_whois(['evil.net'])

    mock_phase_cls.assert_not_called()
    assert any('out of scope' in str(c.args[0]) for c in console.console.print.call_args_list)


def test_command_whois_rolls_back_the_session_when_it_fails(mocker):
    session = MagicMock()
    console = make_console(session)
    mocker.patch('view.console.WhoisPhase').return_value.run.side_effect = ValueError('boom')

    console.command_whois(['example.com'])

    session.rollback.assert_called_once()
    assert any('Error fetching whois data' in str(c.args[0]) for c in console.console.print.call_args_list)


def test_command_scan_runs_scan_phase_and_displays_results(mocker):
    session = make_session()
    console = make_console(session)

    host = Host(nome='alvo', addr='192.0.2.10', ports_active='[22]')
    session.add(host)
    session.commit()
    service = Service(host_id=host.id, port=22, protocol='tcp', state='open', product='OpenSSH', version='8.9p1')
    session.add(service)
    session.commit()
    session.add(ExploitMatch(service_id=service.id, title='OpenSSH exploit', edb_id='1'))
    session.commit()

    mock_phase_cls = mocker.patch('view.console.ScanPhase')
    mock_phase_cls.return_value.run.return_value = host

    console.command_scan(['alvo', '192.0.2.10'])

    mock_phase_cls.return_value.run.assert_called_once_with(
        name='alvo', target='192.0.2.10', on_progress=console._report_progress
    )
    assert console.console.print.called


def test_command_scan_result_shows_guessed_service_name_when_product_is_unknown(mocker):
    """Same real gap as `test_command_services_shows_guessed_service_name_when_product_is_unknown`,
    but for the 'Scan Result' table printed right after a `scan` run."""
    session = make_session()
    console = make_console(session)

    host = Host(nome='alvo', addr='192.0.2.10', ports_active='[9200]')
    session.add(host)
    session.commit()
    session.add(Service(host_id=host.id, port=9200, protocol='tcp', state='open', name='elasticsearch'))
    session.commit()

    mock_phase_cls = mocker.patch('view.console.ScanPhase')
    mock_phase_cls.return_value.run.return_value = host

    console.command_scan(['alvo', '192.0.2.10'])

    title = "Scan Result: alvo (192.0.2.10)"
    services = _table_cell_values(console.console.print, title, 'Service')
    assert services == ['elasticsearch']


def test_command_scan_requires_name_and_target():
    session = make_session()
    console = make_console(session)

    console.command_scan(['so-um-argumento'])

    console.console.print.assert_called_once()


def test_command_scan_reports_missing_tool_without_crashing(mocker):
    session = make_session()
    console = make_console(session)

    mock_phase_cls = mocker.patch('view.console.ScanPhase')
    mock_phase_cls.return_value.run.side_effect = RuntimeError("'rustscan' not found in PATH.")

    console.command_scan(['alvo', '192.0.2.10'])

    assert console.console.print.called


class _AlwaysAvailable:
    @classmethod
    def is_available(cls):
        return True


class _NeverAvailable:
    @classmethod
    def is_available(cls):
        return False


def test_ensure_tool_available_skips_prompt_when_already_installed(mocker):
    session = make_session()
    console = make_console(session)
    mock_confirm = mocker.patch('view.console.Confirm.ask')

    assert console._ensure_tool_available('nmap', _AlwaysAvailable, required=True) is True
    mock_confirm.assert_not_called()


def test_ensure_tool_available_installs_when_missing_and_user_confirms(mocker):
    session = make_session()
    console = make_console(session)

    class Toggle:
        available = False

        @classmethod
        def is_available(cls):
            return cls.available

    def fake_install(tool_name):
        Toggle.available = True
        return True

    mocker.patch('view.console.Confirm.ask', return_value=True)
    mocker.patch('view.console.ToolInstaller.install', side_effect=fake_install)

    assert console._ensure_tool_available('rustscan', Toggle, required=True) is True


def test_ensure_tool_available_required_and_declined_blocks(mocker):
    session = make_session()
    console = make_console(session)
    mocker.patch('view.console.Confirm.ask', return_value=False)

    assert console._ensure_tool_available('nmap', _NeverAvailable, required=True) is False


def test_ensure_tool_available_optional_and_declined_does_not_block(mocker):
    session = make_session()
    console = make_console(session)
    mocker.patch('view.console.Confirm.ask', return_value=False)

    assert console._ensure_tool_available('searchsploit', _NeverAvailable, required=False) is True


def test_ensure_tool_available_required_install_fails_blocks(mocker):
    session = make_session()
    console = make_console(session)
    mocker.patch('view.console.Confirm.ask', return_value=True)
    mocker.patch('view.console.ToolInstaller.install', return_value=False)

    assert console._ensure_tool_available('nmap', _NeverAvailable, required=True) is False


def test_command_scan_aborts_when_required_tool_declined(mocker):
    session = make_session()
    console = make_console(session)

    mock_phase_cls = mocker.patch('view.console.ScanPhase')
    fake_phase = mock_phase_cls.return_value
    fake_phase.rustscan = _NeverAvailable
    fake_phase.nmap = _AlwaysAvailable
    fake_phase.searchsploit = _AlwaysAvailable

    mocker.patch('view.console.Confirm.ask', return_value=False)

    console.command_scan(['alvo', '192.0.2.10'])

    fake_phase.run.assert_not_called()


def _table_titles(print_mock):
    from rich.table import Table
    return [call.args[0].title for call in print_mock.call_args_list if call.args and isinstance(call.args[0], Table)]


def _table_cell_values(print_mock, title, column_header):
    """Returns the cells (already rendered as strings) of a specific column of a
    printed `rich` table, looking it up by the table's title and the column's
    header — avoids depending on column position/order in the tests."""
    from rich.table import Table
    for call in print_mock.call_args_list:
        if call.args and isinstance(call.args[0], Table) and call.args[0].title == title:
            table = call.args[0]
            for column in table.columns:
                if column.header == column_header:
                    return list(column._cells)
    return None


def test_command_scan_shows_vulnerability_table_when_present(mocker):
    session = make_session()
    console = make_console(session)

    host = Host(nome='alvo', addr='192.0.2.10', ports_active='[22]')
    session.add(host)
    session.commit()
    service = Service(host_id=host.id, port=22, protocol='tcp', state='open', product='OpenSSH', version='8.9p1')
    session.add(service)
    session.commit()
    session.add(Vulnerability(service_id=service.id, cve='CVE-2023-9999', cvss=9.8, reference='https://vulners.com/cve/CVE-2023-9999'))
    session.commit()

    mock_phase_cls = mocker.patch('view.console.ScanPhase')
    fake_phase = mock_phase_cls.return_value
    fake_phase.rustscan = _AlwaysAvailable
    fake_phase.nmap = _AlwaysAvailable
    fake_phase.searchsploit = _AlwaysAvailable
    fake_phase.vulners = _AlwaysAvailable
    fake_phase.last_vulners_enabled = True
    fake_phase.last_searchsploit_ran = True
    fake_phase.last_searchsploit_error = None
    fake_phase.run.return_value = host

    console.command_scan(['alvo', '192.0.2.10'])

    assert any('Vulnerabilities' in title for title in _table_titles(console.console.print))


def test_handle_scan_warns_when_vulners_unavailable_but_still_scans(mocker):
    session = make_session()
    console = make_console(session)

    host = Host(nome='alvo', addr='192.0.2.10', ports_active='[22]')
    session.add(host)
    session.commit()

    mock_phase_cls = mocker.patch('view.console.ScanPhase')
    fake_phase = mock_phase_cls.return_value
    fake_phase.rustscan = _AlwaysAvailable
    fake_phase.nmap = _AlwaysAvailable
    fake_phase.searchsploit = _AlwaysAvailable
    fake_phase.vulners = _NeverAvailable
    fake_phase.last_vulners_enabled = False
    fake_phase.last_searchsploit_ran = True
    fake_phase.last_searchsploit_error = None
    fake_phase.run.return_value = host

    console.command_scan(['alvo', '192.0.2.10'])

    fake_phase.run.assert_called_once()
    printed = [str(call.args[0]) for call in console.console.print.call_args_list if call.args]
    assert any('vulners' in text for text in printed)


def test_command_scan_shows_message_when_vulners_ran_and_found_nothing_relevant(mocker):
    """Reproduces a real user confusion: without this message, 'it ran and found
    nothing' is indistinguishable from 'it didn't run at all' — the screen simply
    shows nothing."""
    session = make_session()
    console = make_console(session)

    host = Host(nome='alvo', addr='127.0.0.1', ports_active='[22]')
    session.add(host)
    session.commit()
    service = Service(host_id=host.id, port=22, protocol='tcp', state='open', product='OpenSSH', version='9.6p1')
    session.add(service)
    session.commit()
    # No Vulnerability and no ExploitMatch — vulners ran but found nothing
    # relevant, and because of that searchsploit didn't even get to run (same
    # logic as ScanPhase: it only runs searchsploit if vulners finds something
    # >= min_cvss).

    mock_phase_cls = mocker.patch('view.console.ScanPhase')
    fake_phase = mock_phase_cls.return_value
    fake_phase.rustscan = _AlwaysAvailable
    fake_phase.nmap = _AlwaysAvailable
    fake_phase.searchsploit = _AlwaysAvailable
    fake_phase.vulners = _AlwaysAvailable
    fake_phase.last_vulners_enabled = True
    fake_phase.last_searchsploit_ran = False
    fake_phase.last_searchsploit_error = None
    fake_phase.run.return_value = host

    console.command_scan(['alvo', '127.0.0.1'])

    printed = [str(call.args[0]) for call in console.console.print.call_args_list if call.args]
    assert any('No relevant vulnerabilities' in text for text in printed)
    assert any('searchsploit' in text and 'did not run' in text for text in printed)


def test_command_scan_shows_message_when_searchsploit_ran_and_found_nothing(mocker):
    session = make_session()
    console = make_console(session)

    host = Host(nome='alvo', addr='192.0.2.10', ports_active='[22]')
    session.add(host)
    session.commit()
    service = Service(host_id=host.id, port=22, protocol='tcp', state='open', product='OpenSSH', version='8.9p1')
    session.add(service)
    session.commit()
    # No ExploitMatch — searchsploit ran (unconditionally, vulners unavailable)
    # and found nothing.

    mock_phase_cls = mocker.patch('view.console.ScanPhase')
    fake_phase = mock_phase_cls.return_value
    fake_phase.rustscan = _AlwaysAvailable
    fake_phase.nmap = _AlwaysAvailable
    fake_phase.searchsploit = _AlwaysAvailable
    fake_phase.vulners = _NeverAvailable
    fake_phase.last_vulners_enabled = False
    fake_phase.last_searchsploit_ran = True
    fake_phase.last_searchsploit_error = None
    fake_phase.run.return_value = host

    console.command_scan(['alvo', '192.0.2.10'])

    printed = [str(call.args[0]) for call in console.console.print.call_args_list if call.args]
    assert any('No matching exploit' in text for text in printed)


def test_command_scan_shows_message_when_searchsploit_fails_at_runtime(mocker):
    """Reproduces the user's second real-world error: `searchsploit` in PATH
    (found 'available') but actually failing at runtime (in this case, missing
    xmllint) can no longer take down the whole scan — it needs to show up as a
    specific warning, distinct from 'it ran and found nothing'."""
    session = make_session()
    console = make_console(session)

    host = Host(nome='alvo', addr='127.0.0.1', ports_active='[22]')
    session.add(host)
    session.commit()
    service = Service(host_id=host.id, port=22, protocol='tcp', state='open', product='OpenSSH', version='9.6p1')
    session.add(service)
    session.commit()

    mock_phase_cls = mocker.patch('view.console.ScanPhase')
    fake_phase = mock_phase_cls.return_value
    fake_phase.rustscan = _AlwaysAvailable
    fake_phase.nmap = _AlwaysAvailable
    fake_phase.searchsploit = _AlwaysAvailable
    fake_phase.vulners = _NeverAvailable
    fake_phase.last_vulners_enabled = False
    fake_phase.last_searchsploit_ran = False
    fake_phase.last_searchsploit_error = (
        "Command '['searchsploit', '--nmap', '/tmp/x.xml', '-j']' returned non-zero exit status 1."
    )
    fake_phase.run.return_value = host

    console.command_scan(['alvo', '127.0.0.1'])

    printed = [str(call.args[0]) for call in console.console.print.call_args_list if call.args]
    assert any('searchsploit' in text and 'failed' in text for text in printed)


def test_command_scan_groups_exploits_into_one_table_per_service(mocker):
    """Real UX problem reported by the user: every exploit found (SSH, CUPS,
    Redis, ...) used to land in a single flat table with no indication of
    which port/service it was for. `ScanPhase` now attributes each
    `ExploitMatch` to its own `Service` (see test_scan_phase.py); the console
    must render that as one table per service instead of one giant list."""
    session = make_session()
    console = make_console(session)

    host = Host(nome='alvo', addr='127.0.0.1', ports_active='[22,6379]')
    session.add(host)
    session.commit()
    ssh = Service(host_id=host.id, port=22, protocol='tcp', state='open', product='OpenSSH', version='9.6p1')
    redis = Service(host_id=host.id, port=6379, protocol='tcp', state='open', product='Redis key-value store', version='5.0.7')
    session.add_all([ssh, redis])
    session.commit()
    session.add(ExploitMatch(service_id=ssh.id, title='OpenSSH exploit', edb_id='1'))
    session.add(ExploitMatch(service_id=redis.id, title='Redis exploit', edb_id='2'))
    session.commit()

    mock_phase_cls = mocker.patch('view.console.ScanPhase')
    mock_phase_cls.return_value.run.return_value = host

    console.command_scan(['alvo', '127.0.0.1'])

    titles = _table_titles(console.console.print)
    ssh_titles = [t for t in titles if t and 'port 22' in t]
    redis_titles = [t for t in titles if t and 'port 6379' in t]
    assert len(ssh_titles) == 1
    assert len(redis_titles) == 1
    assert _table_cell_values(console.console.print, ssh_titles[0], 'Title') == ['OpenSSH exploit']
    assert _table_cell_values(console.console.print, redis_titles[0], 'Title') == ['Redis exploit']


def test_command_scan_shows_cve_confirmed_exploit_first_with_its_cve(mocker):
    """Noise-reduction signal picked with the user: cross-reference each
    exploit's own CVE tag (exploit-db's 'Codes' field, persisted as
    `ExploitMatch.cve_codes`) against the CVEs vulners already confirmed for
    that same service (`Vulnerability.cve`). A confirmed match is shown with
    its CVE and sorted ahead of one with no such overlap."""
    session = make_session()
    console = make_console(session)

    host = Host(nome='alvo', addr='127.0.0.1', ports_active='[6379]')
    session.add(host)
    session.commit()
    service = Service(host_id=host.id, port=6379, protocol='tcp', state='open', product='Redis key-value store', version='5.0.7')
    session.add(service)
    session.commit()
    session.add(Vulnerability(service_id=service.id, cve='CVE-2018-12453', cvss=7.5, reference='https://vulners.com/cve/CVE-2018-12453'))
    # Added in an order where the confirmed one is NOT already first, to prove
    # sorting (not insertion order) puts it there.
    session.add(ExploitMatch(service_id=service.id, title='Redis-cli < 5.0 - Buffer Overflow (PoC)', edb_id='44904', cve_codes='CVE-2018-12326'))
    session.add(ExploitMatch(service_id=service.id, title='Redis 5.0 - Denial of Service', edb_id='44908', cve_codes='CVE-2018-12453'))
    session.commit()

    mock_phase_cls = mocker.patch('view.console.ScanPhase')
    mock_phase_cls.return_value.run.return_value = host

    console.command_scan(['alvo', '127.0.0.1'])

    title = next(t for t in _table_titles(console.console.print) if t and 'port 6379' in t)
    titles = _table_cell_values(console.console.print, title, 'Title')
    cves = _table_cell_values(console.console.print, title, 'CVE')

    assert titles[0] == 'Redis 5.0 - Denial of Service'
    assert cves[0] == 'CVE-2018-12453'
    assert titles[1] == 'Redis-cli < 5.0 - Buffer Overflow (PoC)'
    assert cves[1] == '-'


def test_command_scan_caps_exploit_rows_per_service_and_notes_how_many_are_hidden(mocker):
    """`searchsploit -t <product>` can return dozens of undifferentiated
    version-agnostic hits for a common product (e.g. OpenSSH) — capping the
    table keeps the screen scannable, with a note instead of silently
    dropping results."""
    session = make_session()
    console = make_console(session)

    host = Host(nome='alvo', addr='127.0.0.1', ports_active='[22]')
    session.add(host)
    session.commit()
    service = Service(host_id=host.id, port=22, protocol='tcp', state='open', product='OpenSSH', version='9.6p1')
    session.add(service)
    session.commit()
    for i in range(12):
        session.add(ExploitMatch(service_id=service.id, title=f'OpenSSH exploit {i}', edb_id=str(i)))
    session.commit()

    mock_phase_cls = mocker.patch('view.console.ScanPhase')
    mock_phase_cls.return_value.run.return_value = host

    console.command_scan(['alvo', '127.0.0.1'])

    title = next(t for t in _table_titles(console.console.print) if t and 'port 22' in t)
    titles = _table_cell_values(console.console.print, title, 'Title')
    assert len(titles) == 10

    printed = [str(call.args[0]) for call in console.console.print.call_args_list if call.args]
    assert any('+2 more' in text for text in printed)


def test_handle_scan_prints_each_progress_step_as_scan_phase_reports_it(mocker):
    """User's request: instead of a single static message ("Scanning...") sitting
    there until the whole scan finishes, each step (rustscan / nmap / searchsploit)
    should show up on the console as it actually happens."""
    session = make_session()
    console = make_console(session)

    host = Host(nome='alvo', addr='192.0.2.10', ports_active='[22]')
    session.add(host)
    session.commit()

    mock_phase_cls = mocker.patch('view.console.ScanPhase')
    fake_phase = mock_phase_cls.return_value
    fake_phase.rustscan = _AlwaysAvailable
    fake_phase.nmap = _AlwaysAvailable
    fake_phase.searchsploit = _AlwaysAvailable
    fake_phase.vulners = _AlwaysAvailable
    fake_phase.last_vulners_enabled = True
    fake_phase.last_searchsploit_ran = True
    fake_phase.last_searchsploit_error = None

    steps = [
        'Scanning open ports (rustscan)...',
        'Fingerprinting services and versions, with CVE/CVSS correlation (nmap -sV + vulners)...',
        'Looking up matching exploits (searchsploit)...',
    ]

    def fake_run(name, target, on_progress=None):
        for step in steps:
            if on_progress:
                on_progress(step)
        return host

    fake_phase.run.side_effect = fake_run

    console.command_scan(['alvo', '192.0.2.10'])

    printed = [str(call.args[0]) for call in console.console.print.call_args_list if call.args]
    for step in steps:
        assert any(step in text for text in printed), f'step not printed: {step}'


# ---------------------------------------------------------------------------
# `hosts` / `services` / `vulns` — querying and clearing data, in the spirit of
# msfconsole's commands of the same name (which also list and delete with `-d`).
# ---------------------------------------------------------------------------

def _seed_host_with_data(session, addr='192.0.2.10', nome='alvo'):
    host = Host(nome=nome, addr=addr, ports_active='[22]')
    session.add(host)
    session.commit()
    service = Service(host_id=host.id, port=22, protocol='tcp', state='open', product='OpenSSH', version='8.9p1')
    session.add(service)
    session.commit()
    session.add(Vulnerability(service_id=service.id, cve='CVE-2024-0001', cvss=9.8, reference='https://vulners.com/cve/CVE-2024-0001'))
    session.add(ExploitMatch(service_id=service.id, title='OpenSSH exploit', edb_id='1'))
    session.commit()
    return host, service


def test_command_hosts_lists_all_hosts():
    session = make_session()
    console = make_console(session)
    _seed_host_with_data(session, addr='192.0.2.10', nome='alvo1')
    _seed_host_with_data(session, addr='192.0.2.11', nome='alvo2')

    console.command_hosts([])

    assert any('Hosts' in title for title in _table_titles(console.console.print))


def test_command_hosts_shows_message_when_no_hosts():
    session = make_session()
    console = make_console(session)

    console.command_hosts([])

    printed = [str(call.args[0]) for call in console.console.print.call_args_list if call.args]
    assert any('No hosts registered' in text for text in printed)


def test_command_hosts_delete_by_addr_removes_host_and_cascades():
    session = make_session()
    console = make_console(session)
    host, service = _seed_host_with_data(session)

    console.command_hosts(['-d', '192.0.2.10'])

    assert session.query(Host).count() == 0
    assert session.query(Service).count() == 0
    assert session.query(Vulnerability).count() == 0
    assert session.query(ExploitMatch).count() == 0


def test_command_hosts_delete_by_addr_unknown_shows_error():
    session = make_session()
    console = make_console(session)

    console.command_hosts(['-d', '203.0.113.99'])

    printed = [str(call.args[0]) for call in console.console.print.call_args_list if call.args]
    assert any('not found' in text for text in printed)


def test_command_hosts_delete_all_confirmed_removes_everything(mocker):
    session = make_session()
    console = make_console(session)
    _seed_host_with_data(session, addr='192.0.2.10', nome='alvo1')
    _seed_host_with_data(session, addr='192.0.2.11', nome='alvo2')
    mocker.patch('view.console.Confirm.ask', return_value=True)

    console.command_hosts(['-d', 'all'])

    assert session.query(Host).count() == 0
    assert session.query(Service).count() == 0


def test_command_hosts_delete_all_declined_keeps_hosts(mocker):
    session = make_session()
    console = make_console(session)
    _seed_host_with_data(session)
    mocker.patch('view.console.Confirm.ask', return_value=False)

    console.command_hosts(['-d', 'all'])

    assert session.query(Host).count() == 1


def test_command_hosts_delete_without_target_shows_usage():
    session = make_session()
    console = make_console(session)

    console.command_hosts(['-d'])

    printed = [str(call.args[0]) for call in console.console.print.call_args_list if call.args]
    assert any('Usage' in text for text in printed)


def test_command_services_lists_all_services():
    session = make_session()
    console = make_console(session)
    _seed_host_with_data(session, addr='192.0.2.10', nome='alvo1')
    _seed_host_with_data(session, addr='192.0.2.11', nome='alvo2')

    console.command_services([])

    assert any('Services' in title for title in _table_titles(console.console.print))


def test_command_services_shows_guessed_service_name_when_product_is_unknown():
    """Real gap reported by the user: ports nmap couldn't fingerprint a product for
    (product/version both None) showed a bare '?' in the Service column even when
    nmap's own port-table guess (`Service.name`, e.g. 'elasticsearch') was available."""
    session = make_session()
    console = make_console(session)
    host = Host(nome='alvo', addr='192.0.2.10', ports_active='[9200]')
    session.add(host)
    session.commit()
    session.add(Service(host_id=host.id, port=9200, protocol='tcp', state='open', name='elasticsearch'))
    session.commit()

    console.command_services([])

    services = _table_cell_values(console.console.print, 'Services', 'Service')
    assert services == ['elasticsearch']


def test_command_services_filtered_by_host_addr():
    session = make_session()
    console = make_console(session)
    _seed_host_with_data(session, addr='192.0.2.10', nome='alvo1')
    _seed_host_with_data(session, addr='192.0.2.11', nome='alvo2')

    console.command_services(['192.0.2.10'])

    table_calls = [call.args[0] for call in console.console.print.call_args_list if call.args and hasattr(call.args[0], 'rows')]
    assert any('Services' in getattr(t, 'title', '') for t in table_calls)


def test_command_services_filtered_by_unknown_addr_shows_error():
    session = make_session()
    console = make_console(session)

    console.command_services(['203.0.113.99'])

    printed = [str(call.args[0]) for call in console.console.print.call_args_list if call.args]
    assert any('not found' in text for text in printed)


def test_command_services_delete_by_host_addr_removes_services_only():
    session = make_session()
    console = make_console(session)
    host, service = _seed_host_with_data(session)

    console.command_services(['-d', '192.0.2.10'])

    assert session.query(Host).count() == 1
    assert session.query(Service).count() == 0
    assert session.query(Vulnerability).count() == 0
    assert session.query(ExploitMatch).count() == 0


def test_command_services_delete_all_confirmed(mocker):
    session = make_session()
    console = make_console(session)
    _seed_host_with_data(session, addr='192.0.2.10', nome='alvo1')
    _seed_host_with_data(session, addr='192.0.2.11', nome='alvo2')
    mocker.patch('view.console.Confirm.ask', return_value=True)

    console.command_services(['-d', 'all'])

    assert session.query(Service).count() == 0
    assert session.query(Host).count() == 2


def test_command_services_delete_all_declined_keeps_services(mocker):
    session = make_session()
    console = make_console(session)
    _seed_host_with_data(session)
    mocker.patch('view.console.Confirm.ask', return_value=False)

    console.command_services(['-d', 'all'])

    assert session.query(Service).count() == 1


def test_command_services_delete_without_target_shows_usage():
    session = make_session()
    console = make_console(session)

    console.command_services(['-d'])

    printed = [str(call.args[0]) for call in console.console.print.call_args_list if call.args]
    assert any('Usage' in text for text in printed)


def test_command_vulns_lists_all_vulns():
    session = make_session()
    console = make_console(session)
    _seed_host_with_data(session)

    console.command_vulns([])

    assert any('Vulnerabilities' in title for title in _table_titles(console.console.print))


def test_command_vulns_filtered_by_unknown_addr_shows_error():
    session = make_session()
    console = make_console(session)

    console.command_vulns(['203.0.113.99'])

    printed = [str(call.args[0]) for call in console.console.print.call_args_list if call.args]
    assert any('not found' in text for text in printed)


def test_command_vulns_delete_by_host_addr_removes_only_vulnerabilities():
    session = make_session()
    console = make_console(session)
    host, service = _seed_host_with_data(session)

    console.command_vulns(['-d', '192.0.2.10'])

    assert session.query(Vulnerability).count() == 0
    assert session.query(Service).count() == 1
    assert session.query(ExploitMatch).count() == 1


def test_command_vulns_delete_all_confirmed(mocker):
    session = make_session()
    console = make_console(session)
    _seed_host_with_data(session, addr='192.0.2.10', nome='alvo1')
    _seed_host_with_data(session, addr='192.0.2.11', nome='alvo2')
    mocker.patch('view.console.Confirm.ask', return_value=True)

    console.command_vulns(['-d', 'all'])

    assert session.query(Vulnerability).count() == 0
    assert session.query(Service).count() == 2


# ---------------------------------------------------------------------------
# User's request: "show which service/port that vuln belongs to" — the
# vulnerabilities table (in `scan` and in `vulns`) needs to show port/service.
#
# Note: an earlier pass also added a cross-check against Ubuntu's official CVE
# tracker (to catch cases where `vulners` flags a CVE that the distro already
# patched via backport). The user later asked to remove that verification
# step entirely — it doesn't generalize well across distros/environments and
# isn't the project's scope for now (see CLAUDE.md) — so only the port/service
# display remains here.
# ---------------------------------------------------------------------------

def test_command_scan_vulnerability_table_shows_port(mocker):
    session = make_session()
    console = make_console(session)

    host = Host(nome='alvo', addr='192.0.2.10', ports_active='[22]')
    session.add(host)
    session.commit()
    service = Service(
        host_id=host.id, port=22, protocol='tcp', state='open',
        product='OpenSSH', version='9.6p1 Ubuntu-3ubuntu13.18',
    )
    session.add(service)
    session.commit()
    session.add(Vulnerability(
        service_id=service.id, cve='CVE-2024-6387', cvss=8.1,
        reference='https://vulners.com/cve/CVE-2024-6387',
    ))
    session.commit()

    mock_phase_cls = mocker.patch('view.console.ScanPhase')
    fake_phase = mock_phase_cls.return_value
    fake_phase.rustscan = _AlwaysAvailable
    fake_phase.nmap = _AlwaysAvailable
    fake_phase.searchsploit = _AlwaysAvailable
    fake_phase.vulners = _AlwaysAvailable
    fake_phase.last_vulners_enabled = True
    fake_phase.last_searchsploit_ran = True
    fake_phase.last_searchsploit_error = None
    fake_phase.run.return_value = host

    console.command_scan(['alvo', '192.0.2.10'])

    title = "Vulnerabilities (CVE/CVSS via vulners)"
    ports = _table_cell_values(console.console.print, title, 'Port')
    assert ports == ['22']


def test_command_vulns_lists_show_port_and_service():
    session = make_session()
    console = make_console(session)
    host, service = _seed_host_with_data(session)

    console.command_vulns([])

    ports = _table_cell_values(console.console.print, 'Vulnerabilities', 'Port')
    services = _table_cell_values(console.console.print, 'Vulnerabilities', 'Service')
    assert ports == ['22']
    assert any('OpenSSH' in s for s in services)


def test_command_vulns_shows_guessed_service_name_when_product_is_unknown():
    """Same real gap as the `services`/scan-result cases, for the `vulns` table."""
    session = make_session()
    console = make_console(session)
    host = Host(nome='alvo', addr='192.0.2.10', ports_active='[9200]')
    session.add(host)
    session.commit()
    service = Service(host_id=host.id, port=9200, protocol='tcp', state='open', name='elasticsearch')
    session.add(service)
    session.commit()
    session.add(Vulnerability(
        service_id=service.id, cve='CVE-2024-9999', cvss=7.5,
        reference='https://vulners.com/cve/CVE-2024-9999',
    ))
    session.commit()

    console.command_vulns([])

    services = _table_cell_values(console.console.print, 'Vulnerabilities', 'Service')
    assert services == ['elasticsearch']


def _seed_two_runs(session):
    """A host scanned twice: the old run found port 22, the latest found port 80."""
    from model.service_model import ScanRun

    host = Host(nome='alvo', addr='192.0.2.50', ports_active='[80]')
    session.add(host)
    session.commit()
    old_run = ScanRun(host_id=host.id, status='ok')
    session.add(old_run)
    session.commit()
    new_run = ScanRun(host_id=host.id, status='ok')
    session.add(new_run)
    session.commit()
    old = Service(host_id=host.id, scan_run_id=old_run.id, port=22, state='open', product='OpenSSH')
    new = Service(host_id=host.id, scan_run_id=new_run.id, port=80, state='open', product='nginx')
    session.add_all([old, new])
    session.commit()
    session.add(Vulnerability(service_id=old.id, cve='CVE-2024-1111', cvss=9.0))
    session.add(Vulnerability(service_id=new.id, cve='CVE-2024-2222', cvss=7.5))
    session.commit()
    return host


def test_command_services_shows_only_the_latest_scan_run():
    session = make_session()
    console = make_console(session)
    _seed_two_runs(session)

    console.command_services([])

    assert _table_cell_values(console.console.print, 'Services', 'Port') == ['80']


def test_command_vulns_shows_only_the_latest_scan_run():
    session = make_session()
    console = make_console(session)
    _seed_two_runs(session)

    console.command_vulns([])

    assert _table_cell_values(console.console.print, 'Vulnerabilities', 'CVE') == ['CVE-2024-2222']


def test_command_scan_rolls_back_the_session_when_the_scan_fails(mocker):
    """Real bug in use: after one failed scan (IntegrityError during flush) the
    shared session stayed poisoned, so every later `scan` failed with "This
    Session's transaction has been rolled back" even for valid input."""
    session = MagicMock()
    console = make_console(session)
    mock_phase_cls = mocker.patch('view.console.ScanPhase')
    fake_phase = mock_phase_cls.return_value
    fake_phase.rustscan = fake_phase.nmap = fake_phase.searchsploit = fake_phase.vulners = _AlwaysAvailable
    fake_phase.run.side_effect = ValueError('boom')

    console.command_scan(['alvo', '192.0.2.10'])

    session.rollback.assert_called_once()


def _seed_runs_for_history(session):
    from datetime import datetime, timedelta

    from model.service_model import ScanRun

    host = Host(nome='alvo', addr='192.0.2.70')
    session.add(host)
    session.commit()
    start = datetime(2026, 10, 2, 12, 0, 0)
    runs = []
    for index, (status, ports) in enumerate([('ok', [22, 80]), ('failed', []), ('ok', [22, 443])]):
        run = ScanRun(host_id=host.id, status=status, started_at=start + timedelta(hours=index),
                      finished_at=start + timedelta(hours=index, seconds=30))
        session.add(run)
        session.commit()
        for port in ports:
            session.add(Service(host_id=host.id, scan_run_id=run.id, port=port, state='open', product='svc'))
        session.commit()
        runs.append(run)
    return host, runs


def test_command_scans_lists_runs_with_status_and_port_count():
    session = make_session()
    console = make_console(session)
    host, runs = _seed_runs_for_history(session)

    console.command_scans([])

    assert _table_cell_values(console.console.print, 'Scan runs', 'Run') == [str(r.id) for r in reversed(runs)]
    assert _table_cell_values(console.console.print, 'Scan runs', 'Status') == ['ok', 'failed', 'ok']
    assert _table_cell_values(console.console.print, 'Scan runs', 'Services') == ['2', '0', '2']


def test_command_scans_filtered_by_unknown_addr_shows_error():
    session = make_session()
    console = make_console(session)

    console.command_scans(['203.0.113.99'])

    printed = [str(call.args[0]) for call in console.console.print.call_args_list if call.args]
    assert any('not found' in text for text in printed)


def test_command_scan_diff_compares_the_last_two_finished_runs_ignoring_failed_ones():
    session = make_session()
    console = make_console(session)
    _seed_runs_for_history(session)

    console.command_scan(['diff', '192.0.2.70'])

    changes = _table_cell_values(console.console.print, 'Scan diff', 'Change')
    ports = _table_cell_values(console.console.print, 'Scan diff', 'Port')
    assert sorted(zip(changes, ports)) == [('closed', '80'), ('opened', '443')]


def test_command_scan_diff_needs_two_finished_runs():
    session = make_session()
    console = make_console(session)
    host = Host(nome='alvo', addr='192.0.2.71')
    session.add(host)
    session.commit()

    console.command_scan(['diff', '192.0.2.71'])

    printed = [str(call.args[0]) for call in console.console.print.call_args_list if call.args]
    assert any('at least two' in text for text in printed)


def test_command_scan_diff_reports_when_nothing_changed():
    session = make_session()
    console = make_console(session)
    from model.service_model import ScanRun

    host = Host(nome='alvo', addr='192.0.2.72')
    session.add(host)
    session.commit()
    for _ in range(2):
        run = ScanRun(host_id=host.id, status='ok')
        session.add(run)
        session.commit()
        session.add(Service(host_id=host.id, scan_run_id=run.id, port=22, state='open', product='svc'))
        session.commit()

    console.command_scan(['diff', '192.0.2.72'])

    printed = [str(call.args[0]) for call in console.console.print.call_args_list if call.args]
    assert any('No changes' in text for text in printed)


def _printed(console):
    return [str(call.args[0]) for call in console.console.print.call_args_list if call.args]


def test_find_host_accepts_the_scan_name_as_well_as_the_address():
    session = make_session()
    console = make_console(session)
    host = Host(nome='16bits', addr='127.0.0.1')
    session.add(host)
    session.commit()

    assert console._find_host_or_warn('127.0.0.1') is host
    assert console._find_host_or_warn('16bits') is host


def test_find_host_prefers_address_over_a_name_that_looks_like_it():
    session = make_session()
    console = make_console(session)
    by_addr = Host(nome='alvo', addr='10.0.0.1')
    by_name = Host(nome='10.0.0.1', addr='10.0.0.2')
    session.add_all([by_addr, by_name])
    session.commit()

    assert console._find_host_or_warn('10.0.0.1') is by_addr


def test_find_host_warns_when_a_name_matches_several_hosts():
    session = make_session()
    console = make_console(session)
    session.add_all([Host(nome='16bits', addr='10.0.0.1'), Host(nome='16bits', addr='10.0.0.2')])
    session.commit()

    assert console._find_host_or_warn('16bits') is None
    text = ' '.join(_printed(console))
    assert 'ambiguous' in text and '10.0.0.1' in text and '10.0.0.2' in text


def test_command_scan_diff_accepts_the_scan_name():
    session = make_session()
    console = make_console(session)
    host, _ = _seed_runs_for_history(session)  # nome='alvo'

    console.command_scan(['diff', 'alvo'])

    assert _table_cell_values(console.console.print, 'Scan diff', 'Change') is not None


def test_command_scan_diff_without_target_shows_usage():
    session = make_session()
    console = make_console(session)

    console.command_scan(['diff'])

    assert any('Usage: scan diff' in t for t in _printed(console))


def _real_context_console():
    from core.context import SessionContext

    console = make_console(make_session())
    console.context = SessionContext()
    return console


def test_command_set_changes_an_option_and_options_shows_it():
    console = _real_context_console()

    console.command_set(['rustscan_batch', '300'])
    console.command_options([])

    assert console.context.get('rustscan_batch') == 300
    assert '300' in _table_cell_values(console.console.print, 'Options', 'Value')
    assert 'rustscan_batch' in _table_cell_values(console.console.print, 'Options', 'Option')


def test_command_set_accepts_a_value_with_spaces():
    console = _real_context_console()

    console.command_set(['user_agent', 'Mozilla/5.0', '(X11;', 'Linux)'])

    assert console.context.get('user_agent') == 'Mozilla/5.0 (X11; Linux)'


def test_command_set_reports_invalid_input_without_crashing():
    console = _real_context_console()

    console.command_set([])
    console.command_set(['rustscan_batch'])
    console.command_set(['rustscan_batch', 'abc'])
    console.command_set(['nope', '1'])

    assert console.context.get('rustscan_batch') == 4500
    assert len([t for t in _printed(console) if 'red' in t]) == 4


def test_command_unset_restores_default():
    console = _real_context_console()
    console.command_set(['rustscan_timeout', '9000'])

    console.command_unset(['rustscan_timeout'])

    assert console.context.get('rustscan_timeout') == 3000


def test_handle_scan_builds_the_scan_phase_with_the_session_options(mocker):
    console = _real_context_console()
    console.command_set(['rustscan_batch', '200'])
    console.command_set(['rustscan_timeout', '9000'])
    mock_phase_cls = mocker.patch('view.console.ScanPhase')
    mock_phase_cls.return_value.rustscan = _NeverAvailable
    mocker.patch('view.console.Confirm.ask', return_value=False)

    console.command_scan(['alvo', '192.0.2.10'])

    mock_phase_cls.assert_called_once_with(console.session_db, rustscan_batch=200, rustscan_timeout=9000)


def _scope_console():
    return make_console(make_session())


def test_scope_add_exclude_list_and_remove():
    console = _scope_console()

    console.command_scope(['add', 'Example.com'])
    console.command_scope(['add', '10.0.0.0/8'])
    console.command_scope(['exclude', 'admin.example.com'])
    console.command_scope([])

    assert sorted(_table_cell_values(console.console.print, 'Scope', 'Value')) == [
        '10.0.0.0/8', 'admin.example.com', 'example.com']
    assert sorted(_table_cell_values(console.console.print, 'Scope', 'Rule')) == ['exclude', 'include', 'include']

    console.command_scope(['remove', 'example.com'])
    assert console.session_db.query(ScopeRule).count() == 2


def test_scope_add_same_value_again_flips_it_instead_of_duplicating():
    console = _scope_console()

    console.command_scope(['add', 'example.com'])
    console.command_scope(['exclude', 'example.com'])

    rule = console.session_db.query(ScopeRule).one()
    assert rule.allow is False


def test_scope_reports_bad_usage_and_invalid_values():
    console = _scope_console()

    console.command_scope(['add'])
    console.command_scope(['add', 'not valid'])
    console.command_scope(['remove', 'unknown.com'])
    console.command_scope(['bogus'])

    assert len([t for t in _printed(console) if 'red' in t or 'yellow' in t]) == 4
    assert console.session_db.query(ScopeRule).count() == 0


def test_scan_is_blocked_before_anything_runs_when_target_is_out_of_scope(mocker):
    console = _scope_console()
    console.command_scope(['add', 'example.com'])
    mock_phase_cls = mocker.patch('view.console.ScanPhase')

    console.command_scan(['alvo', '192.0.2.10'])

    mock_phase_cls.assert_not_called()
    assert any('out of scope' in t for t in _printed(console))
    assert console.session_db.query(Host).count() == 0


def test_scan_is_blocked_for_an_excluded_target(mocker):
    console = _scope_console()
    console.command_scope(['add', '10.0.0.0/8'])
    console.command_scope(['exclude', '10.0.0.5'])
    mock_phase_cls = mocker.patch('view.console.ScanPhase')

    console.command_scan(['alvo', '10.0.0.5'])

    mock_phase_cls.assert_not_called()
    assert any('excluded' in t for t in _printed(console))


def test_scan_runs_when_target_is_in_scope(mocker):
    console = _scope_console()
    console.command_scope(['add', 'example.com'])
    mock_phase_cls = mocker.patch('view.console.ScanPhase')
    mock_phase_cls.return_value.rustscan = _NeverAvailable
    mocker.patch('view.console.Confirm.ask', return_value=False)

    console.command_scan(['alvo', 'erp.example.com'])

    mock_phase_cls.assert_called_once()


def test_scan_with_empty_scope_warns_but_still_runs(mocker):
    console = _scope_console()
    mock_phase_cls = mocker.patch('view.console.ScanPhase')
    mock_phase_cls.return_value.rustscan = _NeverAvailable
    mocker.patch('view.console.Confirm.ask', return_value=False)

    console.command_scan(['alvo', '192.0.2.10'])

    mock_phase_cls.assert_called_once()
    assert any('No scope defined' in t for t in _printed(console))


def test_command_recon_requires_name_and_domain():
    console = _scope_console()

    console.command_recon(['alvo'])

    assert any('Usage: recon' in t for t in _printed(console))


def test_command_recon_blocked_when_out_of_scope(mocker):
    console = _scope_console()
    console.command_scope(['add', 'example.com'])
    mock_phase_cls = mocker.patch('view.console.ReconPhase')

    console.command_recon(['alvo', 'evil.net'])

    mock_phase_cls.assert_not_called()
    assert any('out of scope' in t for t in _printed(console))


def test_command_recon_reports_missing_tool_without_crashing(mocker):
    console = _scope_console()
    mock_phase_cls = mocker.patch('view.console.ReconPhase')
    mock_phase_cls.return_value.subfinder = _NeverAvailable
    mocker.patch('view.console.Confirm.ask', return_value=False)

    console.command_recon(['alvo', 'example.com'])

    mock_phase_cls.return_value.run.assert_not_called()
    assert any('subfinder is still unavailable' in t for t in _printed(console))


def test_command_recon_shows_subdomains_marking_the_new_ones(mocker):
    session = make_session()
    console = make_console(session)
    console.context = SessionContext()
    host = Host(nome='alvo', addr='example.com')
    session.add(host)
    session.commit()

    mock_phase_cls = mocker.patch('view.console.ReconPhase')
    fake_phase = mock_phase_cls.return_value
    fake_phase.subfinder = _AlwaysAvailable
    fake_phase.run.return_value = host
    fake_phase.last_new_subdomains = ['beta.example.com']
    fake_phase.last_all_subdomains = ['api.example.com', 'beta.example.com']

    console.command_recon(['alvo', 'example.com'])

    names = _table_cell_values(console.console.print, 'Subdomains', 'Name')
    status = _table_cell_values(console.console.print, 'Subdomains', 'Status')
    assert sorted(zip(names, status)) == [('api.example.com', 'known'), ('beta.example.com', 'new')]


def test_command_recon_rolls_back_the_session_when_it_fails(mocker):
    session = MagicMock()
    console = make_console(session)
    console.context = SessionContext()
    mock_phase_cls = mocker.patch('view.console.ReconPhase')
    mock_phase_cls.return_value.subfinder = _AlwaysAvailable
    mock_phase_cls.return_value.run.side_effect = ValueError('boom')

    console.command_recon(['alvo', 'example.com'])

    session.rollback.assert_called_once()


def test_command_recon_passes_the_subfinder_command_as_progress_callback(mocker):
    session = make_session()
    console = make_console(session)
    console.context = SessionContext()
    host = Host(nome='alvo', addr='example.com')
    session.add(host)
    session.commit()

    mock_phase_cls = mocker.patch('view.console.ReconPhase')
    fake_phase = mock_phase_cls.return_value
    fake_phase.subfinder = _AlwaysAvailable
    fake_phase.run.return_value = host
    fake_phase.last_new_subdomains = []
    fake_phase.last_all_subdomains = []

    console.command_recon(['alvo', 'example.com'])

    mock_phase_cls.return_value.run.assert_called_once_with(
        name='alvo', domain='example.com', on_progress=console._report_progress
    )


def _seed_subdomains(session, addr='192.0.2.80', nome='alvo'):
    from model.subdomain_model import Subdomain

    host = Host(nome=nome, addr=addr)
    session.add(host)
    session.commit()
    session.add_all([
        Subdomain(host_id=host.id, name='api.' + addr),
        Subdomain(host_id=host.id, name='www.' + addr),
    ])
    session.commit()
    return host


def test_command_subdomains_lists_all():
    session = make_session()
    console = make_console(session)
    _seed_subdomains(session, addr='192.0.2.80', nome='alvo1')
    _seed_subdomains(session, addr='192.0.2.81', nome='alvo2')

    console.command_subdomains([])

    names = _table_cell_values(console.console.print, 'Subdomains', 'Name')
    assert sorted(names) == ['api.192.0.2.80', 'api.192.0.2.81', 'www.192.0.2.80', 'www.192.0.2.81']


def test_command_subdomains_filtered_by_host():
    session = make_session()
    console = make_console(session)
    _seed_subdomains(session, addr='192.0.2.80', nome='alvo1')
    _seed_subdomains(session, addr='192.0.2.81', nome='alvo2')

    console.command_subdomains(['alvo1'])

    names = _table_cell_values(console.console.print, 'Subdomains', 'Name')
    assert sorted(names) == ['api.192.0.2.80', 'www.192.0.2.80']


def test_command_subdomains_filtered_by_unknown_host_shows_error():
    session = make_session()
    console = make_console(session)

    console.command_subdomains(['nope'])

    assert any('not found' in t for t in _printed(console))


def test_command_subdomains_with_none_found_says_so():
    session = make_session()
    console = make_console(session)

    console.command_subdomains([])

    assert any('No subdomains' in t for t in _printed(console))


def test_command_subdomains_delete_by_host_keeps_the_host():
    session = make_session()
    console = make_console(session)
    host = _seed_subdomains(session)

    console.command_subdomains(['-d', 'alvo'])

    assert session.query(Host).count() == 1
    from model.subdomain_model import Subdomain
    assert session.query(Subdomain).count() == 0


def test_command_subdomains_delete_requires_a_target():
    session = make_session()
    console = make_console(session)

    console.command_subdomains(['-d'])

    assert any('Usage: subdomains -d' in t for t in _printed(console))


def test_command_subdomains_delete_all_confirmed(mocker):
    session = make_session()
    console = make_console(session)
    _seed_subdomains(session, addr='192.0.2.80', nome='alvo1')
    _seed_subdomains(session, addr='192.0.2.81', nome='alvo2')
    mocker.patch('view.console.Confirm.ask', return_value=True)

    console.command_subdomains(['-d', 'all'])

    from model.subdomain_model import Subdomain
    assert session.query(Subdomain).count() == 0
    assert session.query(Host).count() == 2


def test_command_subdomains_delete_all_declined(mocker):
    session = make_session()
    console = make_console(session)
    _seed_subdomains(session)
    mocker.patch('view.console.Confirm.ask', return_value=False)

    console.command_subdomains(['-d', 'all'])

    from model.subdomain_model import Subdomain
    assert session.query(Subdomain).count() == 2


def _fuzz_console():
    console = _scope_console()
    console.context.set('fuzz_wordlist', '/tmp/words.txt')
    return console


def test_command_fuzz_requires_name_and_url():
    console = _fuzz_console()

    console.command_fuzz(['alvo'])

    assert any('Usage: fuzz' in t for t in _printed(console))


def test_command_fuzz_requires_a_url_scheme():
    console = _fuzz_console()

    console.command_fuzz(['alvo', 'example.com/no-scheme'])

    assert any('scheme' in t for t in _printed(console))


def test_command_fuzz_requires_a_configured_wordlist(mocker):
    console = _scope_console()  # fuzz_wordlist left unset
    mock_phase_cls = mocker.patch('view.console.FuzzPhase')

    console.command_fuzz(['alvo', 'http://example.com'])

    mock_phase_cls.assert_not_called()
    assert any('fuzz_wordlist' in t for t in _printed(console))


def test_command_fuzz_blocked_when_out_of_scope(mocker):
    console = _fuzz_console()
    console.command_scope(['add', 'example.com'])
    mock_phase_cls = mocker.patch('view.console.FuzzPhase')

    console.command_fuzz(['alvo', 'http://evil.net/base'])

    mock_phase_cls.assert_not_called()
    assert any('out of scope' in t for t in _printed(console))


def test_command_fuzz_reports_missing_tool_without_crashing(mocker):
    console = _fuzz_console()
    mock_phase_cls = mocker.patch('view.console.FuzzPhase')
    mock_phase_cls.return_value.gobuster = _NeverAvailable
    mocker.patch('view.console.Confirm.ask', return_value=False)

    console.command_fuzz(['alvo', 'http://example.com'])

    mock_phase_cls.return_value.run.assert_not_called()
    assert any('gobuster is still unavailable' in t for t in _printed(console))


def test_command_fuzz_shows_findings_marking_the_new_ones(mocker):
    from phases.fuzz.tools.gobuster_tool import FuzzMatch

    console = _fuzz_console()
    host = Host(nome='alvo', addr='example.com')
    console.session_db.add(host)
    console.session_db.commit()

    mock_phase_cls = mocker.patch('view.console.FuzzPhase')
    fake_phase = mock_phase_cls.return_value
    fake_phase.gobuster = _AlwaysAvailable
    fake_phase.run.return_value = host
    fake_phase.last_new_paths = ['/secret']
    fake_phase.last_all_matches = [
        FuzzMatch(path='/admin', status_code=301, size=169, redirect='http://example.com/admin/'),
        FuzzMatch(path='/secret', status_code=200, size=1, redirect=None),
    ]

    console.command_fuzz(['alvo', 'http://example.com'])

    paths = _table_cell_values(console.console.print, 'Findings', 'Path')
    status = _table_cell_values(console.console.print, 'Findings', 'Status')
    assert sorted(zip(paths, status)) == [('/admin', 'known'), ('/secret', 'new')]
    mock_phase_cls.return_value.run.assert_called_once_with(
        name='alvo', url='http://example.com', wordlist='/tmp/words.txt',
        extensions=None, threads=10, status_codes=None,
        on_progress=console._report_progress,
    )


def test_command_fuzz_passes_configured_extensions_and_threads(mocker):
    console = _fuzz_console()
    console.context.set('fuzz_extensions', 'php,bak')
    console.context.set('fuzz_threads', '50')
    host = Host(nome='alvo', addr='example.com')
    console.session_db.add(host)
    console.session_db.commit()
    mock_phase_cls = mocker.patch('view.console.FuzzPhase')
    fake_phase = mock_phase_cls.return_value
    fake_phase.gobuster = _AlwaysAvailable
    fake_phase.run.return_value = host
    fake_phase.last_new_paths = []
    fake_phase.last_all_matches = []

    console.command_fuzz(['alvo', 'http://example.com'])

    mock_phase_cls.return_value.run.assert_called_once_with(
        name='alvo', url='http://example.com', wordlist='/tmp/words.txt',
        extensions='php,bak', threads=50, status_codes=None,
        on_progress=console._report_progress,
    )


def test_command_fuzz_rolls_back_the_session_when_it_fails(mocker):
    session = MagicMock()
    console = make_console(session)
    console.context = SessionContext()
    console.context.set('fuzz_wordlist', '/tmp/words.txt')
    mock_phase_cls = mocker.patch('view.console.FuzzPhase')
    mock_phase_cls.return_value.gobuster = _AlwaysAvailable
    mock_phase_cls.return_value.run.side_effect = ValueError('boom')

    console.command_fuzz(['alvo', 'http://example.com'])

    session.rollback.assert_called_once()


def test_run_wraps_the_loop_in_patch_stdout_so_rich_tables_do_not_get_corrupted(mocker):
    """Real bug reported by the user: a wide `rich` table (the `fuzz` Findings
    table) came out with its left border missing on every data row. Reproduced
    the exact same table standalone (outside the console) and it rendered
    correctly — so the corruption isn't in how the table is built, it's from
    `rich.Console.print` writing to stdout while `prompt_toolkit`'s
    PromptSession is also managing the terminal's cursor/redraw between
    prompts, with neither library aware of the other's writes. prompt_toolkit's
    own `patch_stdout()` exists specifically to make prints safe during an
    active prompt session."""
    console = InteractiveConsole.__new__(InteractiveConsole)
    console.console = MagicMock()
    console.prompt_session = MagicMock()
    console.prompt_session.prompt.side_effect = EOFError()
    patch_stdout_fn = mocker.patch('view.console.patch_stdout')

    console.run()

    # raw=True is required: by default the proxy escapes ESC bytes, so every
    # `rich` color/border sequence would show up literally as `?[36m`.
    patch_stdout_fn.assert_called_once_with(raw=True)
    patch_stdout_fn.return_value.__enter__.assert_called_once()
    patch_stdout_fn.return_value.__exit__.assert_called_once()


# --- crawl (SpiderPhase) -------------------------------------------------

def _fake_spider_phase(mocker, host, pages=(), new_pages=(), emails=None, new_emails=()):
    from phases.web.tools.crawler import CrawledUrl

    mock_phase_cls = mocker.patch('view.console.SpiderPhase')
    fake_phase = mock_phase_cls.return_value
    fake_phase.run.return_value = host
    fake_phase.last_all_pages = [CrawledUrl(*p) for p in pages]
    fake_phase.last_new_pages = list(new_pages)
    fake_phase.last_all_emails = emails or {}
    fake_phase.last_new_emails = list(new_emails)
    return mock_phase_cls


def test_command_crawl_requires_name_and_url():
    console = _scope_console()

    console.command_crawl(['alvo'])

    assert any('Usage: crawl' in t for t in _printed(console))


def test_command_crawl_requires_a_scheme_and_host():
    console = _scope_console()

    console.command_crawl(['alvo', 'example.com'])

    assert any('scheme and host' in t for t in _printed(console))


def test_command_crawl_blocked_when_out_of_scope(mocker):
    console = _scope_console()
    console.command_scope(['add', 'example.com'])
    mock_phase_cls = mocker.patch('view.console.SpiderPhase')

    console.command_crawl(['alvo', 'http://evil.net/'])

    mock_phase_cls.assert_not_called()
    assert any('out of scope' in t for t in _printed(console))


def test_command_crawl_passes_session_options_and_a_scope_check(mocker):
    session = make_session()
    console = make_console(session)
    console.command_set(['spider_max_depth', '2'])
    console.command_set(['spider_max_pages', '30'])
    console.command_set(['spider_delay', '1.5'])
    console.command_set(['user_agent', 'Custom/1.0'])
    console.command_scope(['exclude', 'admin.example.com'])
    host = Host(nome='alvo', addr='example.com')
    session.add(host)
    session.commit()
    mock_phase_cls = _fake_spider_phase(mocker, host)

    console.command_crawl(['alvo', 'http://example.com/'])

    kwargs = mock_phase_cls.return_value.run.call_args.kwargs
    assert (kwargs['name'], kwargs['url']) == ('alvo', 'http://example.com/')
    assert (kwargs['max_depth'], kwargs['max_pages'], kwargs['delay'], kwargs['user_agent']) == (
        2, 30, 1.5, 'Custom/1.0',
    )
    assert kwargs['on_progress'] == console._report_progress
    # the callback consults the same scope rules `scan`/`recon` use
    assert kwargs['scope_allows']('www.example.com') is True
    assert kwargs['scope_allows']('admin.example.com') is False


def test_command_crawl_shows_pages_and_emails_marking_the_new_ones(mocker):
    session = make_session()
    console = make_console(session)
    host = Host(nome='alvo', addr='example.com')
    session.add(host)
    session.commit()
    _fake_spider_phase(
        mocker, host,
        pages=[('http://example.com/', 200, 0), ('http://example.com/a', 404, 1)],
        new_pages=['http://example.com/a'],
        emails={'admin@example.com': 'http://example.com/'},
        new_emails=['admin@example.com'],
    )

    console.command_crawl(['alvo', 'http://example.com/'])

    urls = _table_cell_values(console.console.print, 'Pages', 'URL')
    status = _table_cell_values(console.console.print, 'Pages', 'Status')
    assert sorted(zip(urls, status)) == [('http://example.com/', 'known'), ('http://example.com/a', 'new')]
    assert _table_cell_values(console.console.print, 'Emails', 'Email') == ['admin@example.com']
    assert _table_cell_values(console.console.print, 'Emails', 'Status') == ['new']


def test_command_crawl_rolls_back_the_session_when_it_fails(mocker):
    session = MagicMock()
    console = make_console(session)
    mocker.patch('view.console.SpiderPhase').return_value.run.side_effect = ValueError('boom')

    console.command_crawl(['alvo', 'http://example.com/'])

    session.rollback.assert_called_once()
    assert any('Error during crawl' in t for t in _printed(console))

