from unittest.mock import MagicMock, patch

import pytest

from phases.recon.tools.subfinder_tool import SubfinderTool


def test_is_available_checks_the_binary_on_path():
    with patch('phases.recon.tools.subfinder_tool.shutil.which', return_value='/usr/bin/subfinder'):
        assert SubfinderTool.is_available() is True
    with patch('phases.recon.tools.subfinder_tool.shutil.which', return_value=None):
        assert SubfinderTool.is_available() is False


def test_find_subdomains_parses_ndjson_output_and_dedupes_case_insensitively():
    stdout = (
        '{"host":"www.example.com","input":"example.com"}\n'
        '{"host":"API.example.com","input":"example.com"}\n'
        '{"host":"www.example.com","input":"example.com"}\n'
    )
    fake_result = MagicMock(stdout=stdout, returncode=0)
    with patch('phases.recon.tools.subfinder_tool.shutil.which', return_value='/usr/bin/subfinder'), \
         patch('phases.recon.tools.subfinder_tool.subprocess.run', return_value=fake_result) as mock_run:
        names = SubfinderTool.find_subdomains('example.com')

    assert names == ['api.example.com', 'www.example.com']
    command = mock_run.call_args[0][0]
    assert command[:2] == ['subfinder', '-d']
    assert 'example.com' in command
    assert '-silent' in command and '-json' in command


def test_find_subdomains_ignores_blank_and_malformed_lines():
    stdout = '\n{"host":"www.example.com"}\nnot json\n   \n'
    fake_result = MagicMock(stdout=stdout, returncode=0)
    with patch('phases.recon.tools.subfinder_tool.shutil.which', return_value='/usr/bin/subfinder'), \
         patch('phases.recon.tools.subfinder_tool.subprocess.run', return_value=fake_result):
        names = SubfinderTool.find_subdomains('example.com')

    assert names == ['www.example.com']


def test_find_subdomains_raises_runtime_error_when_not_installed():
    with patch('phases.recon.tools.subfinder_tool.shutil.which', return_value=None):
        with pytest.raises(RuntimeError, match='subfinder'):
            SubfinderTool.find_subdomains('example.com')
