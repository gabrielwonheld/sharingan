from unittest.mock import MagicMock, patch

from phases.scan.tools.installer import ToolInstaller


def which_only(*names):
    def fake_which(binary):
        return f'/usr/bin/{binary}' if binary in names else None
    return fake_which


def test_install_nmap_uses_apt_when_available():
    fake_result = MagicMock(returncode=0)
    with patch('phases.scan.tools.installer.shutil.which', side_effect=which_only('apt-get')), \
         patch('phases.scan.tools.installer.subprocess.run', return_value=fake_result) as mock_run:
        assert ToolInstaller.install_nmap() is True

    assert mock_run.call_args[0][0] == ['sudo', 'apt-get', 'install', '-y', 'nmap']


def test_install_nmap_falls_back_to_brew_when_no_linux_pkg_manager():
    fake_result = MagicMock(returncode=0)
    with patch('phases.scan.tools.installer.shutil.which', side_effect=which_only('brew')), \
         patch('phases.scan.tools.installer.subprocess.run', return_value=fake_result) as mock_run:
        assert ToolInstaller.install_nmap() is True

    assert mock_run.call_args[0][0] == ['brew', 'install', 'nmap']


def test_install_nmap_returns_false_without_known_package_manager():
    with patch('phases.scan.tools.installer.shutil.which', return_value=None):
        assert ToolInstaller.install_nmap() is False


def test_install_searchsploit_uses_apt_exploitdb_package():
    """On Kali, the apt package is called `exploitdb` (confirmed at kali.org/tools/exploitdb) — not `searchsploit`.
    It also installs `libxml2-utils` (which provides `xmllint`): without it, `searchsploit --nmap`
    exits with 'Please install xmllint' and status 1 — reproduced in real usage (2026-08-30),
    cause confirmed in Sn1per issue #72 ("kali needs xmllint for sniper's call to
    searchsploit"). The `exploitdb` package alone doesn't guarantee this dependency on every distro."""
    fake_result = MagicMock(returncode=0)
    with patch('phases.scan.tools.installer.shutil.which', side_effect=which_only('apt-get')), \
         patch('phases.scan.tools.installer.subprocess.run', return_value=fake_result) as mock_run:
        assert ToolInstaller.install_searchsploit() is True

    assert mock_run.call_args[0][0] == ['sudo', 'apt-get', 'install', '-y', 'exploitdb', 'libxml2-utils']


def test_install_rustscan_prefers_cargo_over_brew():
    """RustScan has no official apt/dnf/pacman package — only cargo and Homebrew count
    as reliable automatic installs (everything else is downloading the .deb manually)."""
    fake_result = MagicMock(returncode=0)
    with patch('phases.scan.tools.installer.shutil.which', side_effect=which_only('cargo', 'brew')), \
         patch('phases.scan.tools.installer.subprocess.run', return_value=fake_result) as mock_run:
        assert ToolInstaller.install_rustscan() is True

    assert mock_run.call_args[0][0] == ['cargo', 'install', 'rustscan']


def test_install_rustscan_ignores_apt_since_theres_no_package():
    with patch('phases.scan.tools.installer.shutil.which', side_effect=which_only('apt-get')):
        assert ToolInstaller.install_rustscan() is False


def test_install_dispatches_by_tool_name():
    with patch.object(ToolInstaller, 'install_nmap', return_value=True) as mock_install:
        assert ToolInstaller.install('nmap') is True
        mock_install.assert_called_once()


def test_install_returns_false_for_unknown_tool():
    assert ToolInstaller.install('unknown-tool') is False


def test_manual_install_hint_has_content_for_known_tools():
    for tool in ('nmap', 'rustscan', 'searchsploit', 'vulners'):
        assert ToolInstaller.manual_install_hint(tool)


def test_install_subfinder_uses_apt_when_available():
    """subfinder is packaged on Kali's apt (kali.org/tools/subfinder)."""
    fake_result = MagicMock(returncode=0)
    with patch('phases.scan.tools.installer.shutil.which', side_effect=which_only('apt-get')), \
         patch('phases.scan.tools.installer.subprocess.run', return_value=fake_result) as mock_run:
        assert ToolInstaller.install_subfinder() is True

    assert mock_run.call_args[0][0] == ['sudo', 'apt-get', 'install', '-y', 'subfinder']


def test_install_subfinder_falls_back_to_brew():
    fake_result = MagicMock(returncode=0)
    with patch('phases.scan.tools.installer.shutil.which', side_effect=which_only('brew')), \
         patch('phases.scan.tools.installer.subprocess.run', return_value=fake_result) as mock_run:
        assert ToolInstaller.install_subfinder() is True

    assert mock_run.call_args[0][0] == ['brew', 'install', 'subfinder']


def test_install_subfinder_falls_back_to_go_install_as_last_resort():
    fake_result = MagicMock(returncode=0)
    with patch('phases.scan.tools.installer.shutil.which', side_effect=which_only('go')), \
         patch('phases.scan.tools.installer.subprocess.run', return_value=fake_result) as mock_run:
        assert ToolInstaller.install_subfinder() is True

    assert mock_run.call_args[0][0] == [
        'go', 'install', 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
    ]


def test_install_subfinder_returns_false_without_any_known_method():
    with patch('phases.scan.tools.installer.shutil.which', return_value=None):
        assert ToolInstaller.install_subfinder() is False


def test_install_dispatches_subfinder():
    with patch.object(ToolInstaller, 'install_subfinder', return_value=True) as mock_installer:
        assert ToolInstaller.install('subfinder') is True
    mock_installer.assert_called_once()


def test_manual_install_hint_mentions_subfinder_sources():
    hint = ToolInstaller.manual_install_hint('subfinder')
    assert 'projectdiscovery' in hint.lower()
