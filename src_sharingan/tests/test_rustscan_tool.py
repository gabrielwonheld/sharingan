from unittest.mock import MagicMock, patch

import pytest

from phases.scan.tools.rustscan_tool import RustscanTool


def test_scan_ports_parses_greppable_output():
    fake_result = MagicMock(stdout='192.0.2.10 -> [22,80,443]\n', returncode=0)

    with patch('phases.scan.tools.rustscan_tool.shutil.which', return_value='/usr/bin/rustscan'), \
         patch('phases.scan.tools.rustscan_tool.subprocess.run', return_value=fake_result) as mock_run:
        ports = RustscanTool.scan_ports('192.0.2.10')

    assert ports == [22, 80, 443]
    mock_run.assert_called_once()
    # `--no-nmap` was removed from RustScan (confirmed in the current source, src/input.rs, and
    # in the "Bring back --no-nmap!" issue #650) — passing that flag makes clap reject the
    # arguments and the process exit with status 2. `-g/--greppable` alone already avoids
    # rustscan's embedded nmap (that's the whole reason it exists: just print host -> ports).
    command = mock_run.call_args[0][0]
    assert '--no-nmap' not in command
    assert '-g' in command


def test_scan_ports_does_not_pass_removed_no_nmap_flag():
    """Regression: `--no-nmap` no longer exists in current RustScan — passing it makes
    clap reject the arguments (usage error) and the subprocess exit with status 2, which
    `subprocess.run(..., check=True)` turns into a `CalledProcessError`."""
    fake_result = MagicMock(stdout='192.0.2.10 -> [22]\n', returncode=0)

    with patch('phases.scan.tools.rustscan_tool.shutil.which', return_value='/usr/bin/rustscan'), \
         patch('phases.scan.tools.rustscan_tool.subprocess.run', return_value=fake_result) as mock_run:
        RustscanTool.scan_ports('192.0.2.10')

    assert '--no-nmap' not in mock_run.call_args[0][0]


def test_scan_ports_ignores_lines_without_ports():
    fake_result = MagicMock(stdout='No host responded\n192.0.2.10 -> [22]\n', returncode=0)

    with patch('phases.scan.tools.rustscan_tool.shutil.which', return_value='/usr/bin/rustscan'), \
         patch('phases.scan.tools.rustscan_tool.subprocess.run', return_value=fake_result):
        ports = RustscanTool.scan_ports('192.0.2.10')

    assert ports == [22]


def test_scan_ports_raises_when_binary_missing():
    with patch('phases.scan.tools.rustscan_tool.shutil.which', return_value=None):
        with pytest.raises(RuntimeError):
            RustscanTool.scan_ports('192.0.2.10')


def test_scan_ports_passes_custom_batch_and_timeout_to_rustscan():
    fake_result = MagicMock(stdout='192.0.2.10 -> [22]\n', returncode=0)

    with patch('phases.scan.tools.rustscan_tool.shutil.which', return_value='/usr/bin/rustscan'), \
         patch('phases.scan.tools.rustscan_tool.subprocess.run', return_value=fake_result) as mock_run:
        RustscanTool.scan_ports('192.0.2.10', timeout_ms=9000, batch_size=200)

    command = mock_run.call_args[0][0]
    assert command[command.index('-b') + 1] == '200'
    assert command[command.index('-t') + 1] == '9000'
