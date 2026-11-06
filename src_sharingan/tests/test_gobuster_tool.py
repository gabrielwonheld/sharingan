from unittest.mock import patch

import pytest

from phases.fuzz.tools.gobuster_tool import FuzzMatch, GobusterError, GobusterTool


def fake_runner(returncode=0, stdout='', stderr=''):
    """A stand-in for `_run_streaming`: records the command it was given and
    returns a canned (returncode, stdout, stderr), so tests never spawn gobuster
    or touch the network."""
    calls = []

    def runner(command, timeout):
        calls.append(command)
        result = results.pop(0) if results else (returncode, stdout, stderr)
        return result

    results: list = []
    runner.calls = calls
    runner.queue = results  # push (rc, out, err) tuples to script multiple runs
    return runner


def _available():
    return patch('phases.fuzz.tools.gobuster_tool.shutil.which', return_value='/usr/bin/gobuster')


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
    runner = fake_runner(stdout=stdout)
    with _available():
        matches = GobusterTool.enumerate('http://example.com', '/tmp/words.txt', runner=runner)

    assert matches == [
        FuzzMatch(path='/admin', status_code=301, size=169, redirect='http://example.com/admin/'),
        FuzzMatch(path='/index.html', status_code=200, size=1234, redirect=None),
    ]
    command = runner.calls[0]
    assert command[:2] == ['gobuster', 'dir']
    assert command[command.index('-u') + 1] == 'http://example.com'
    assert command[command.index('-w') + 1] == '/tmp/words.txt'
    assert '--no-error' in command
    # `-q` must NOT be passed: it suppresses gobuster's own live progress counter,
    # which is exactly the "is it running or stuck?" signal we want the user to see.
    assert '-q' not in command


def test_enumerate_raises_when_gobuster_exits_non_zero_without_a_length():
    # Non-zero exit with no parseable wildcard length (e.g. a bad wordlist): nothing
    # to auto-calibrate, so it must surface as an error, never a silent "0 findings".
    runner = fake_runner(returncode=1, stderr='Error: something else went wrong\n')
    with _available():
        with pytest.raises(GobusterError, match='fuzz_exclude_length'):
            GobusterTool.enumerate('http://example.com', '/tmp/words.txt', runner=runner)


def test_enumerate_auto_calibrates_past_a_wildcard_using_gobusters_reported_length():
    # Real repro: a wildcard/catch-all makes gobuster abort naming the exact length
    # it saw. We re-run automatically telling it to exclude that length — the way
    # feroxbuster self-calibrates — instead of making the user read and set it.
    runner = fake_runner()
    runner.queue.append((
        1, '',
        'Error: the server returns a status code that matches the provided options '
        'for non existing urls. http://example.com/5f3a => 301 (Length: 795).\n',
    ))
    runner.queue.append((0, '/real (Status: 200) [Size: 10]\n', ''))
    notices = []

    with _available():
        matches = GobusterTool.enumerate(
            'http://example.com', '/tmp/words.txt', runner=runner, on_notice=notices.append,
        )

    assert matches == [FuzzMatch(path='/real', status_code=200, size=10, redirect=None)]
    # second run carried the length gobuster itself reported
    assert runner.calls[1][runner.calls[1].index('--exclude-length') + 1] == '795'
    assert any('795' in n for n in notices)


def test_enumerate_does_not_auto_calibrate_when_user_set_an_exclude_length():
    # If the user pinned a length and gobuster still refuses, don't silently retry
    # with a different value — report it (the catch-all length likely varies).
    runner = fake_runner(
        returncode=1,
        stderr='... => 301 (Length: 820).\n',
    )
    with _available():
        with pytest.raises(GobusterError, match='varies'):
            GobusterTool.enumerate(
                'http://example.com', '/tmp/words.txt', exclude_length='795', runner=runner,
            )
    # only one run — no auto retry
    assert len(runner.calls) == 1


def test_enumerate_auto_calibration_gives_up_after_one_retry():
    # The catch-all length varies per path: the retry (with the first length) also
    # fails. It must not loop forever — one retry, then a clear error.
    runner = fake_runner()
    runner.queue.append((1, '', '... => 301 (Length: 795).\n'))
    runner.queue.append((1, '', '... => 301 (Length: 812).\n'))
    with _available():
        with pytest.raises(GobusterError):
            GobusterTool.enumerate('http://example.com', '/tmp/words.txt', runner=runner)
    assert len(runner.calls) == 2


def test_enumerate_strips_ansi_escapes_from_result_lines():
    stdout = '\r\x1b[2K/secret.txt           (Status: 200) [Size: 3]\n'
    runner = fake_runner(stdout=stdout)
    with _available():
        matches = GobusterTool.enumerate('http://example.com', '/tmp/words.txt', runner=runner)

    assert matches == [FuzzMatch(path='/secret.txt', status_code=200, size=3, redirect=None)]


def test_enumerate_passes_exclude_length_when_given():
    runner = fake_runner()
    with _available():
        GobusterTool.enumerate('http://example.com', '/tmp/words.txt', exclude_length='459', runner=runner)

    command = runner.calls[0]
    assert command[command.index('--exclude-length') + 1] == '459'


def test_enumerate_omits_exclude_length_when_not_given():
    runner = fake_runner()
    with _available():
        GobusterTool.enumerate('http://example.com', '/tmp/words.txt', runner=runner)

    assert '--exclude-length' not in runner.calls[0]


def test_enumerate_ignores_banner_and_blank_lines():
    stdout = '===============================================================\n\n/secret (Status: 200) [Size: 1]\n'
    runner = fake_runner(stdout=stdout)
    with _available():
        matches = GobusterTool.enumerate('http://example.com', '/tmp/words.txt', runner=runner)

    assert matches == [FuzzMatch(path='/secret', status_code=200, size=1, redirect=None)]


def test_enumerate_passes_extensions_threads_and_status_codes():
    runner = fake_runner()
    with _available():
        GobusterTool.enumerate(
            'http://example.com', '/tmp/words.txt',
            extensions='php,bak', threads=50, status_codes='200,301', runner=runner,
        )

    command = runner.calls[0]
    assert command[command.index('-x') + 1] == 'php,bak'
    assert command[command.index('-t') + 1] == '50'
    assert command[command.index('-s') + 1] == '200,301'


def test_enumerate_raises_runtime_error_when_not_installed():
    with patch('phases.fuzz.tools.gobuster_tool.shutil.which', return_value=None):
        with pytest.raises(RuntimeError, match='gobuster'):
            GobusterTool.enumerate('http://example.com', '/tmp/words.txt')


def test_wildcard_length_parses_gobusters_error():
    assert GobusterTool._wildcard_length('... => 301 (Length: 795).') == 795
    assert GobusterTool._wildcard_length('nothing here') is None
    assert GobusterTool._wildcard_length('') is None
