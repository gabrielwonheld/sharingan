import pytest

from model.crawl_model import CrawledPage, HarvestedEmail
from model.finding_model import Finding
from model.host import Host
from model.scope_model import ScopeRule
from model.service_model import ScanRun, Service, Vulnerability
from model.subdomain_model import Subdomain
from model.workspace_model import Workspace
from test_console import _printed, _table_cell_values, make_console, make_session


def make_workspace_console():
    session = make_session()
    session.add(Workspace(id=1, name='default'))
    session.commit()
    return make_console(session), session


def text(console):
    return ' '.join(_printed(console))


# --- the command ---------------------------------------------------------

def test_workspace_lists_workspaces_marking_the_current_one_with_host_counts():
    console, session = make_workspace_console()
    session.add(Workspace(id=2, name='cliente-a'))
    session.add_all([Host(nome='a', addr='1.1.1.1', workspace_id=2), Host(nome='b', addr='2.2.2.2', workspace_id=2)])
    session.commit()

    console.command_workspace([])

    printed = console.console.print
    names = _table_cell_values(printed, 'Workspaces', 'Name')
    assert names == ['default', 'cliente-a']
    assert _table_cell_values(printed, 'Workspaces', 'Current') == ['*', '']
    assert _table_cell_values(printed, 'Workspaces', 'Hosts') == ['0', '2']


def test_workspace_add_creates_and_switches_to_it():
    console, session = make_workspace_console()

    console.command_workspace(['add', 'cliente-a'])

    assert console.workspace_name == 'cliente-a'
    assert console.workspace_id == session.query(Workspace).filter_by(name='cliente-a').one().id
    assert 'cliente-a' in text(console)


def test_workspace_add_rejects_duplicates_bad_names_and_reserved_words():
    console, session = make_workspace_console()
    console.command_workspace(['add', 'cliente-a'])
    count = session.query(Workspace).count()

    for bad in ('cliente-a', 'has space', 'a/b', '', 'add', 'delete', 'x' * 41):
        console.command_workspace(['add', bad] if bad else ['add'])

    assert session.query(Workspace).count() == count


def test_workspace_switch_by_name_and_unknown_name():
    console, session = make_workspace_console()
    session.add(Workspace(id=2, name='cliente-a'))
    session.commit()

    console.command_workspace(['cliente-a'])
    assert (console.workspace_id, console.workspace_name) == (2, 'cliente-a')

    console.command_workspace(['nope'])
    assert console.workspace_name == 'cliente-a'
    assert "Workspace 'nope' not found" in text(console)
    assert "workspace add nope" in text(console)


def test_workspace_delete_asks_for_confirmation(mocker):
    console, session = make_workspace_console()
    session.add(Workspace(id=2, name='cliente-a'))
    session.add_all([Host(nome='a', addr='1.1.1.1', workspace_id=2),
                     ScopeRule(kind='ip', value='1.1.1.1', workspace_id=2),
                     Host(nome='keep', addr='9.9.9.9', workspace_id=1)])
    session.commit()
    confirm = mocker.patch('view.console.Confirm.ask', return_value=False)

    console.command_workspace(['delete', 'cliente-a'])
    assert session.query(Workspace).count() == 2

    confirm.return_value = True
    console.command_workspace(['delete', 'cliente-a'])
    assert session.query(Workspace).count() == 1
    assert [h.addr for h in session.query(Host)] == ['9.9.9.9']
    assert session.query(ScopeRule).count() == 0


def test_deleting_the_current_workspace_returns_to_default(mocker):
    console, session = make_workspace_console()
    console.command_workspace(['add', 'cliente-a'])
    mocker.patch('view.console.Confirm.ask', return_value=True)

    console.command_workspace(['delete', 'cliente-a'])

    assert (console.workspace_id, console.workspace_name) == (1, 'default')


def test_the_default_workspace_cannot_be_deleted(mocker):
    console, session = make_workspace_console()
    confirm = mocker.patch('view.console.Confirm.ask', return_value=True)

    console.command_workspace(['delete', 'default'])

    assert session.query(Workspace).count() == 1
    confirm.assert_not_called()
    assert 'default' in text(console) and 'cannot' in text(console)


def test_workspace_delete_unknown_and_usage():
    console, _ = make_workspace_console()

    console.command_workspace(['delete', 'nope'])
    console.command_workspace(['delete'])

    assert "not found" in text(console)
    assert 'Usage: workspace delete' in text(console)


# --- the prompt ------------------------------------------------------------

def test_prompt_shows_the_current_workspace():
    console, _ = make_workspace_console()

    assert ''.join(t for _, t in console._prompt_message()) == 'Sharingan [default] > '

    console.command_workspace(['add', 'cliente-a'])

    assert ''.join(t for _, t in console._prompt_message()) == 'Sharingan [cliente-a] > '


def test_the_workspace_name_has_its_own_style_class():
    console, _ = make_workspace_console()

    classes = [style for style, _ in console._prompt_message()]

    assert 'class:workspace' in classes and 'class:prompt' in classes


# --- isolation: every command only sees the current workspace --------------

def _seed_subdomains(session, host):
    session.add(Subdomain(host_id=host.id, name=f'api.{host.addr}'))


def _seed_services(session, host):
    session.add(Service(host_id=host.id, port=22, protocol='tcp', state='open', product='OpenSSH'))


def _seed_vulns(session, host):
    service = Service(host_id=host.id, port=22, protocol='tcp', state='open', product='OpenSSH')
    session.add(service)
    session.commit()
    session.add(Vulnerability(service_id=service.id, cve='CVE-2024-0001', cvss=9.0))


def _seed_scans(session, host):
    session.add(ScanRun(host_id=host.id, status='ok'))


def _seed_findings(session, host):
    session.add(Finding(host_id=host.id, url=f'http://{host.addr}', path='/admin', status_code=200))


def _seed_pages(session, host):
    session.add(CrawledPage(host_id=host.id, url=f'http://{host.addr}/', status_code=200, depth=0))


def _seed_emails(session, host):
    session.add(HarvestedEmail(host_id=host.id, email=f'a@{host.addr}'))


def _seed_hosts(session, host):
    pass


# command, seeder, table title, model queried to count rows
ISOLATED = [
    ('hosts', _seed_hosts, 'Hosts', Host),
    ('subdomains', _seed_subdomains, 'Subdomains', Subdomain),
    ('services', _seed_services, 'Services', Service),
    ('vulns', _seed_vulns, 'Vulnerabilities', Vulnerability),
    ('scans', _seed_scans, 'Scan runs', ScanRun),
    ('findings', _seed_findings, 'Findings', Finding),
    ('pages', _seed_pages, 'Pages', CrawledPage),
    ('emails', _seed_emails, 'Emails', HarvestedEmail),
]


def two_workspaces_with_the_same_address(seeder):
    console, session = make_workspace_console()
    session.add(Workspace(id=2, name='cliente-a'))
    session.commit()
    hosts = {}
    for workspace_id, name in ((1, 'proj-default'), (2, 'proj-a')):
        host = Host(nome=name, addr='10.0.0.1', workspace_id=workspace_id)
        session.add(host)
        session.commit()
        seeder(session, host)
        session.commit()
        hosts[workspace_id] = host
    return console, session, hosts


@pytest.mark.parametrize('command,seeder,title,model', ISOLATED)
def test_listing_only_shows_the_current_workspace(command, seeder, title, model):
    console, session, hosts = two_workspaces_with_the_same_address(seeder)
    console.command_workspace(['cliente-a'])

    getattr(console, f'command_{command}')([])

    rows = _table_cell_values(console.console.print, title, 'Host' if command != 'hosts' else 'Address')
    assert rows == ['10.0.0.1']


# `scans` only lists (it has no `-d`), so it's not part of the delete checks
@pytest.mark.parametrize('command,seeder,title,model', [c for c in ISOLATED if c[0] != 'scans'])
def test_delete_all_only_touches_the_current_workspace(command, seeder, title, model, mocker):
    console, session, hosts = two_workspaces_with_the_same_address(seeder)
    mocker.patch('view.console.Confirm.ask', return_value=True)
    before = session.query(model).count()
    console.command_workspace(['cliente-a'])

    getattr(console, f'command_{command}')(['-d', 'all'])

    assert session.query(Host).filter_by(workspace_id=1).count() == 1  # default workspace untouched
    if command == 'hosts':
        assert session.query(Host).count() == 1
    else:
        assert session.query(model).count() == before - 1
        assert session.query(Host).count() == 2


def test_name_lookup_is_per_workspace_so_repeated_names_do_not_collide():
    console, session = make_workspace_console()
    session.add(Workspace(id=2, name='cliente-a'))
    session.add_all([
        Host(nome='web', addr='10.0.0.1', workspace_id=1),
        Host(nome='web', addr='10.0.0.2', workspace_id=2),
    ])
    session.commit()

    assert console._find_host_or_warn('web').addr == '10.0.0.1'
    console.command_workspace(['cliente-a'])
    assert console._find_host_or_warn('web').addr == '10.0.0.2'
    assert console._find_host_or_warn('10.0.0.1') is None
    assert "not found" in text(console)


def test_a_host_from_another_workspace_is_not_reachable_by_info_or_phases():
    console, session = make_workspace_console()
    session.add(Workspace(id=2, name='cliente-a'))
    session.add(Host(nome='x', addr='10.0.0.9', workspace_id=2))
    session.commit()

    console.command_info(['10.0.0.9'])
    console.command_phases(['10.0.0.9'])

    assert text(console).count('not found') == 2


def test_scope_rules_are_per_workspace(mocker):
    console, session = make_workspace_console()
    console.command_scope(['add', 'example.com'])
    console.command_workspace(['add', 'cliente-a'])

    console.command_scope([])
    assert 'No scope defined' in text(console)
    console.command_scope(['add', 'other.com'])
    console.command_scope([])

    assert _table_cell_values(console.console.print, 'Scope', 'Value') == ['other.com']
    assert sorted((r.workspace_id, r.value) for r in session.query(ScopeRule)) == [(1, 'example.com'), (2, 'other.com')]


def test_scope_enforcement_uses_the_current_workspaces_rules():
    console, session = make_workspace_console()
    console.command_scope(['add', 'example.com'])
    assert console._target_allowed_by_scope('example.com') is True
    assert console._target_allowed_by_scope('evil.net') is False

    console.command_workspace(['add', 'cliente-a'])
    console.command_scope(['add', 'evil.net'])

    assert console._target_allowed_by_scope('evil.net') is True
    assert console._target_allowed_by_scope('example.com') is False
    assert console._scope_allows('evil.net') is True
    assert console._scope_allows('example.com') is False


@pytest.mark.parametrize('command,args,phase', [
    ('recon', ['n', 'example.com'], 'ReconPhase'),
    ('whois', ['example.com'], 'WhoisPhase'),
    ('fuzz', ['n', 'http://example.com'], 'FuzzPhase'),
    ('crawl', ['n', 'http://example.com/'], 'SpiderPhase'),
])
def test_phases_are_built_for_the_current_workspace(command, args, phase, mocker):
    console, session = make_workspace_console()
    console.command_workspace(['add', 'cliente-a'])
    console.command_set(['fuzz_wordlist', '/tmp/w.txt'])
    phase_cls = mocker.patch(f'view.console.{phase}')
    phase_cls.return_value.run.side_effect = RuntimeError('stop here')
    for attr in ('subfinder', 'gobuster'):
        setattr(phase_cls.return_value, attr, type('T', (), {'is_available': staticmethod(lambda: True)}))

    getattr(console, f'command_{command}')(args)

    assert phase_cls.call_args.kwargs['workspace_id'] == console.workspace_id != 1


def test_scan_is_built_for_the_current_workspace(mocker):
    console, session = make_workspace_console()
    console.command_workspace(['add', 'cliente-a'])
    phase_cls = mocker.patch('view.console.ScanPhase')
    phase_cls.return_value.run.side_effect = RuntimeError('stop here')
    tool = type('T', (), {'is_available': staticmethod(lambda: True)})
    phase_cls.return_value.rustscan = phase_cls.return_value.nmap = tool
    phase_cls.return_value.searchsploit = phase_cls.return_value.vulners = tool

    console.handle_scan('n', '10.0.0.1')

    assert phase_cls.call_args.kwargs['workspace_id'] == console.workspace_id != 1
