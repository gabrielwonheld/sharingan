import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from phases.scan.tools.searchsploit_tool import SearchsploitTool


def test_search_product_builds_title_only_search_argv():
    """Real behavior confirmed against a live target (2026-09-17): a plain
    `searchsploit <term> -j` (no `-t`) does full-text search and picks up
    unrelated false positives (e.g. searching "redis" matched a "Dokany" and
    a "Microsoft Windows 10" entry, presumably because "redis" appears
    somewhere in their body text) — `-t` (title-only) avoids that, and is
    what `searchsploit --nmap` itself used internally too."""
    fake_result = MagicMock(stdout=json.dumps({'RESULTS_EXPLOIT': []}), returncode=0)

    with patch('phases.scan.tools.searchsploit_tool.shutil.which', return_value='/usr/bin/searchsploit'), \
         patch('phases.scan.tools.searchsploit_tool.subprocess.run', return_value=fake_result) as mock_run:
        SearchsploitTool.search_product('Redis key-value store')

    mock_run.assert_called_once_with(
        ['searchsploit', '-t', 'Redis key-value store', '-j'],
        capture_output=True,
        text=True,
        check=True,
    )


def test_search_product_parses_results():
    payload = json.dumps({'RESULTS_EXPLOIT': [{'Title': 'OpenSSH 8.9p1 - Example', 'EDB-ID': '12345'}]})
    fake_result = MagicMock(stdout=payload, returncode=0)

    with patch('phases.scan.tools.searchsploit_tool.shutil.which', return_value='/usr/bin/searchsploit'), \
         patch('phases.scan.tools.searchsploit_tool.subprocess.run', return_value=fake_result):
        matches = SearchsploitTool.search_product('OpenSSH')

    assert matches == [{'Title': 'OpenSSH 8.9p1 - Example', 'EDB-ID': '12345'}]


def test_search_product_handles_empty_output():
    fake_result = MagicMock(stdout='', returncode=0)

    with patch('phases.scan.tools.searchsploit_tool.shutil.which', return_value='/usr/bin/searchsploit'), \
         patch('phases.scan.tools.searchsploit_tool.subprocess.run', return_value=fake_result):
        matches = SearchsploitTool.search_product('nonexistent-product')

    assert matches == []


def test_search_product_still_merges_multiple_concatenated_json_objects():
    """`_parse_json` stays robust to more than one concatenated JSON object on
    stdout even though a direct `-t <product> -j` call normally returns just
    one — cheap insurance, and it's what fixed the real "No matching exploit
    found" bug for the old `--nmap` mode this method replaces."""
    first = json.dumps({'RESULTS_EXPLOIT': [{'Title': 'Redis - Example', 'EDB-ID': '1'}]})
    second = json.dumps({'RESULTS_EXPLOIT': [{'Title': 'Redis - Example', 'EDB-ID': '1'}]})
    fake_result = MagicMock(stdout=first + second, returncode=0)

    with patch('phases.scan.tools.searchsploit_tool.shutil.which', return_value='/usr/bin/searchsploit'), \
         patch('phases.scan.tools.searchsploit_tool.subprocess.run', return_value=fake_result):
        matches = SearchsploitTool.search_product('redis')

    assert matches == [{'Title': 'Redis - Example', 'EDB-ID': '1'}]


def test_search_product_raises_called_process_error_on_failure():
    with patch('phases.scan.tools.searchsploit_tool.shutil.which', return_value='/usr/bin/searchsploit'), \
         patch(
             'phases.scan.tools.searchsploit_tool.subprocess.run',
             side_effect=subprocess.CalledProcessError(1, ['searchsploit', '-t', 'redis', '-j']),
         ):
        with pytest.raises(subprocess.CalledProcessError):
            SearchsploitTool.search_product('redis')


def test_is_available_false_when_binary_missing():
    with patch('phases.scan.tools.searchsploit_tool.shutil.which', return_value=None):
        assert SearchsploitTool.is_available() is False


def test_is_available_true_when_searchsploit_present():
    """`is_available()` no longer requires `xmllint` (2026-09-17): that
    requirement only existed because the old `--nmap <xml>` mode shelled out
    to `xmllint` to parse the XML file we handed it. `search_product` does a
    plain text search with no XML involved, so `xmllint` isn't a dependency
    of exploit correlation anymore."""
    with patch('phases.scan.tools.searchsploit_tool.shutil.which', return_value='/usr/bin/searchsploit'):
        assert SearchsploitTool.is_available() is True
