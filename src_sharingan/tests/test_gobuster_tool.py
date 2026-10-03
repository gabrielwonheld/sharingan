from unittest.mock import MagicMock, patch

import pytest

from phases.fuzz.tools.gobuster_tool import FuzzMatch, GobusterTool


def test_is_available_checks_the_binary_on_path():
    with patch('phases.fuzz.tools.gobuster_tool.shutil.which', return_value='/usr/bin/gobuster'):
        assert GobusterTool.is_available() is True
    with patch('phases.fuzz.tools.gobuster_tool.shutil.which', return_value=None):
        assert GobusterTool.is_available() is False


def test_enumerate_parses_status_size_and_redirect():
    stdout = (
        '/admin                (Status: 301) [Size: 169] [--> http://example.com/admin/]\n'
        '/index.html           (Status: 200) [Size: 1234]\n'
    )
    fake_result = MagicMock(stdout=stdout, returncode=0)
    with patch('phases.fuzz.tools.gobuster_tool.shutil.which', return_value='/usr/bin/gobuster'), \
         patch('phases.fuzz.tools.gobuster_tool.subprocess.run', return_value=fake_result) as mock_run:
        matches = GobusterTool.enumerate('http://example.com', '/tmp/words.txt')

    assert matches == [
        FuzzMatch(path='/admin', status_code=301, size=169, redirect='http://example.com/admin/'),
        FuzzMatch(path='/index.html', status_code=200, size=1234, redirect=None),
    ]
    command = mock_run.call_args[0][0]
    assert command[:2] == ['gobuster', 'dir']
    assert command[command.index('-u') + 1] == 'http://example.com'
    assert command[command.index('-w') + 1] == '/tmp/words.txt'
    assert '-q' in command and '--no-error' in command


def test_enumerate_ignores_banner_and_blank_lines():
    stdout = '===============================================================\n\n/secret (Status: 200) [Size: 1]\n'
    fake_result = MagicMock(stdout=stdout, returncode=0)
    with patch('phases.fuzz.tools.gobuster_tool.shutil.which', return_value='/usr/bin/gobuster'), \
         patch('phases.fuzz.tools.gobuster_tool.subprocess.run', return_value=fake_result):
        matches = GobusterTool.enumerate('http://example.com', '/tmp/words.txt')

    assert matches == [FuzzMatch(path='/secret', status_code=200, size=1, redirect=None)]


def test_enumerate_passes_extensions_threads_and_status_codes():
    fake_result = MagicMock(stdout='', returncode=0)
    with patch('phases.fuzz.tools.gobuster_tool.shutil.which', return_value='/usr/bin/gobuster'), \
         patch('phases.fuzz.tools.gobuster_tool.subprocess.run', return_value=fake_result) as mock_run:
        GobusterTool.enumerate(
            'http://example.com', '/tmp/words.txt',
            extensions='php,bak', threads=50, status_codes='200,301',
        )

    command = mock_run.call_args[0][0]
    assert command[command.index('-x') + 1] == 'php,bak'
    assert command[command.index('-t') + 1] == '50'
    assert command[command.index('-s') + 1] == '200,301'


def test_enumerate_raises_runtime_error_when_not_installed():
    with patch('phases.fuzz.tools.gobuster_tool.shutil.which', return_value=None):
        with pytest.raises(RuntimeError, match='gobuster'):
            GobusterTool.enumerate('http://example.com', '/tmp/words.txt')
