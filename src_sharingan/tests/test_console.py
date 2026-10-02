from types import SimpleNamespace
from unittest.mock import MagicMock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.extensions import Base
from model.host import Host
from model.service_model import ExploitMatch, Service, Vulnerability
from view.console import InteractiveConsole


def make_console(session):
    # Avoids the real __init__ (which would open a real PromptSession/DB) and
    # injects only what the handlers use.
    console = InteractiveConsole.__new__(InteractiveConsole)
    console.console = MagicMock()
    console.session_db = session
    return console


def make_session():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


def test_command_whois_parses_domain_correctly(mocker):
    """Before the fix, `command_whois` read `args[1]` — with `whois example.com`
    (args = ['example.com']) that raised an IndexError."""
    session = make_session()
    console = make_console(session)

    fake_record = SimpleNamespace(registrar='Test Registrar', creation_date=None, expiration_date=None)
    mock_service = mocker.patch('view.console.WhoisService')
    mock_service.return_value.perform_whois.return_value = fake_record

    console.command_whois(['example.com'])

    mock_service.return_value.perform_whois.assert_called_once_with('example.com')


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
        name='alvo', target='192.0.2.10', on_progress=console._report_scan_progress
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
