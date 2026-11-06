import subprocess
from unittest.mock import MagicMock, patch

import pytest

from phases.scan.tools.rustscan_tool import RustscanTool


def _fake_popen(stdout: str, returncode: int = 0):
    """Builds a fake Popen whose stdout iterates line by line, like the real one."""
    proc = MagicMock()
    proc.stdout = iter(stdout.splitlines(keepends=True))
    proc.wait.return_value = returncode
    proc.returncode = returncode
    proc.__enter__ = lambda self: self
    proc.__exit__ = lambda self, *a: False
    return proc


def test_scan_ports_parses_greppable_summary_line():
    proc = _fake_popen('Open 192.0.2.10:22\n192.0.2.10 -> [22,80,443]\n')

    with patch('phases.scan.tools.rustscan_tool.shutil.which', return_value='/usr/bin/rustscan'), \
         patch('phases.scan.tools.rustscan_tool.subprocess.Popen', return_value=proc) as mock_popen:
        ports = RustscanTool.scan_ports('192.0.2.10')

    assert ports == [22, 80, 443]
    mock_popen.assert_called_once()
    command = mock_popen.call_args[0][0]
    # `-g/--greppable` suppressed rustscan's incremental `Open host:port` lines, so the
    # user got no feedback during a long scan. `--scripts none` skips the embedded nmap
    # the same way greppable did, while still streaming `Open ...` lines as ports are found.
    assert '-g' not in command
    assert '--scripts' in command
    assert command[command.index('--scripts') + 1] == 'none'


def test_scan_ports_does_not_pass_removed_no_nmap_flag():
    """Regression: `--no-nmap` no longer exists in current RustScan — passing it makes
    clap reject the arguments (usage error) and the subprocess exit with status 2."""
    proc = _fake_popen('192.0.2.10 -> [22]\n')

    with patch('phases.scan.tools.rustscan_tool.shutil.which', return_value='/usr/bin/rustscan'), \
         patch('phases.scan.tools.rustscan_tool.subprocess.Popen', return_value=proc) as mock_popen:
        RustscanTool.scan_ports('192.0.2.10')

    assert '--no-nmap' not in mock_popen.call_args[0][0]


def test_scan_ports_streams_open_port_lines_to_the_callback():
    """So the console can show ports appearing live instead of a frozen 'Scanning...'."""
    proc = _fake_popen('Open 192.0.2.10:22\nOpen 192.0.2.10:80\n192.0.2.10 -> [22,80]\n')
    seen: list[str] = []

    with patch('phases.scan.tools.rustscan_tool.shutil.which', return_value='/usr/bin/rustscan'), \
         patch('phases.scan.tools.rustscan_tool.subprocess.Popen', return_value=proc):
        ports = RustscanTool.scan_ports('192.0.2.10', on_line=seen.append)

    assert ports == [22, 80]
    assert 'Open 192.0.2.10:22' in seen
    assert 'Open 192.0.2.10:80' in seen


def test_scan_ports_ignores_lines_without_ports():
    proc = _fake_popen('No host responded\n192.0.2.10 -> [22]\n')

    with patch('phases.scan.tools.rustscan_tool.shutil.which', return_value='/usr/bin/rustscan'), \
         patch('phases.scan.tools.rustscan_tool.subprocess.Popen', return_value=proc):
        ports = RustscanTool.scan_ports('192.0.2.10')

    assert ports == [22]


def test_scan_ports_raises_when_binary_missing():
    with patch('phases.scan.tools.rustscan_tool.shutil.which', return_value=None):
        with pytest.raises(RuntimeError):
            RustscanTool.scan_ports('192.0.2.10')


def test_scan_ports_raises_on_non_zero_exit():
    proc = _fake_popen('', returncode=2)

    with patch('phases.scan.tools.rustscan_tool.shutil.which', return_value='/usr/bin/rustscan'), \
         patch('phases.scan.tools.rustscan_tool.subprocess.Popen', return_value=proc):
        with pytest.raises(subprocess.CalledProcessError):
            RustscanTool.scan_ports('192.0.2.10')


def test_scan_ports_passes_custom_batch_and_timeout_to_rustscan():
    proc = _fake_popen('192.0.2.10 -> [22]\n')

    with patch('phases.scan.tools.rustscan_tool.shutil.which', return_value='/usr/bin/rustscan'), \
         patch('phases.scan.tools.rustscan_tool.subprocess.Popen', return_value=proc) as mock_popen:
        RustscanTool.scan_ports('192.0.2.10', timeout_ms=9000, batch_size=200)

    command = mock_popen.call_args[0][0]
    assert command[command.index('-b') + 1] == '200'
    assert command[command.index('-t') + 1] == '9000'
