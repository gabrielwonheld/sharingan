from unittest.mock import MagicMock, patch

import pytest

from phases.fuzz.tools.gobuster_tool import FuzzMatch, GobusterError, GobusterTool


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
    assert '--no-error' in command
    # `-q` must NOT be passed: it suppresses gobuster's own live progress counter,
    # which is exactly the "is it running or stuck?" signal we want the user to see.
    assert '-q' not in command
    # stderr is left to inherit the terminal (so the progress counter shows); only
    # stdout is captured for parsing.
    assert mock_run.call_args.kwargs.get('stderr') is None


def test_enumerate_raises_when_gobuster_exits_non_zero():
    # Real repro: a wildcard/catch-all target (every path -> HTTP 200, same length)
    # makes gobuster abort with status 1 before testing the wordlist. Previously
    # this was swallowed and shown as "0 findings", indistinguishable from a real
    # empty result.
    fake_result = MagicMock(stdout='', returncode=1)
    with patch('phases.fuzz.tools.gobuster_tool.shutil.which', return_value='/usr/bin/gobuster'), \
         patch('phases.fuzz.tools.gobuster_tool.subprocess.run', return_value=fake_result):
        with pytest.raises(GobusterError, match='fuzz_exclude_length'):
            GobusterTool.enumerate('http://example.com', '/tmp/words.txt')


def test_enumerate_strips_ansi_escapes_from_result_lines():
    # Without `-q`, gobuster clears its progress line before each hit, so real
    # result lines arrive prefixed with a carriage return + CSI "clear line"
    # escape. The parser must not fold those bytes into the path.
    stdout = '\r\x1b[2K/secret.txt           (Status: 200) [Size: 3]\n'
    fake_result = MagicMock(stdout=stdout, returncode=0)
    with patch('phases.fuzz.tools.gobuster_tool.shutil.which', return_value='/usr/bin/gobuster'), \
         patch('phases.fuzz.tools.gobuster_tool.subprocess.run', return_value=fake_result):
        matches = GobusterTool.enumerate('http://example.com', '/tmp/words.txt')

    assert matches == [FuzzMatch(path='/secret.txt', status_code=200, size=3, redirect=None)]


def test_enumerate_passes_exclude_length_when_given():
    fake_result = MagicMock(stdout='', returncode=0)
    with patch('phases.fuzz.tools.gobuster_tool.shutil.which', return_value='/usr/bin/gobuster'), \
         patch('phases.fuzz.tools.gobuster_tool.subprocess.run', return_value=fake_result) as mock_run:
        GobusterTool.enumerate('http://example.com', '/tmp/words.txt', exclude_length='459')

    command = mock_run.call_args[0][0]
    assert command[command.index('--exclude-length') + 1] == '459'


def test_enumerate_omits_exclude_length_when_not_given():
    fake_result = MagicMock(stdout='', returncode=0)
    with patch('phases.fuzz.tools.gobuster_tool.shutil.which', return_value='/usr/bin/gobuster'), \
         patch('phases.fuzz.tools.gobuster_tool.subprocess.run', return_value=fake_result) as mock_run:
        GobusterTool.enumerate('http://example.com', '/tmp/words.txt')

    assert '--exclude-length' not in mock_run.call_args[0][0]


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
