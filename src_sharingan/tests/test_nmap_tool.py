from unittest.mock import MagicMock, patch

from phases.scan.tools.nmap_tool import NmapTool

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu Linux"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

GUESSED_NAME_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="9200">
        <state state="open"/>
        <service name="wap-wsp" method="table" conf="3"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_xml_extracts_service_fingerprint(tmp_path):
    xml_path = tmp_path / 'scan.xml'
    xml_path.write_text(SAMPLE_XML)

    services = NmapTool._parse_xml(str(xml_path))

    assert len(services) == 2

    ssh = next(s for s in services if s.port == 22)
    assert ssh.state == 'open'
    assert ssh.product == 'OpenSSH'
    assert ssh.version == '8.9p1'
    assert 'OpenSSH' in ssh.banner
    assert ssh.name == 'ssh'

    http = next(s for s in services if s.port == 80)
    assert http.state == 'closed'
    assert http.product is None
    assert http.name == 'http'


def test_parse_xml_extracts_guessed_service_name_when_product_is_unknown(tmp_path):
    """Reproduces the real gap: when nmap -sV can't grab a banner (no product/version
    detected), it still often reports a probable service name guessed from nmap-services'
    port-number table (`method="table"`, as opposed to a confirmed `method="probed"`).
    Before this fix, that guess was silently dropped by `_parse_xml`, leaving the console
    with nothing but '?' for these ports even though nmap already had a hint."""
    xml_path = tmp_path / 'scan.xml'
    xml_path.write_text(GUESSED_NAME_XML)

    services = NmapTool._parse_xml(str(xml_path))

    guessed = next(s for s in services if s.port == 9200)
    assert guessed.product is None
    assert guessed.name == 'wap-wsp'


def test_fingerprint_skips_nmap_when_no_ports():
    with patch('phases.scan.tools.nmap_tool.subprocess.run') as mock_run:
        result = NmapTool.fingerprint('192.0.2.10', [], xml_output_path='/tmp/unused.xml')

    assert result == []
    mock_run.assert_not_called()


def test_fingerprint_builds_expected_command(tmp_path):
    xml_path = tmp_path / 'scan.xml'
    xml_path.write_text(SAMPLE_XML)
    fake_result = MagicMock(returncode=0)

    with patch('phases.scan.tools.nmap_tool.shutil.which', return_value='/usr/bin/nmap'), \
         patch('phases.scan.tools.nmap_tool.subprocess.run', return_value=fake_result) as mock_run:
        services = NmapTool.fingerprint('192.0.2.10', [22, 80], xml_output_path=str(xml_path))

    command = mock_run.call_args[0][0]
    assert '-sV' in command
    assert '22,80' in command
    assert len(services) == 2


def test_fingerprint_includes_extra_args_when_provided(tmp_path):
    """extra_args exists to embed NSE scripts (e.g. vulners) in the same -sV
    command, without NmapTool needing to know anything about vulners specifically."""
    xml_path = tmp_path / 'scan.xml'
    xml_path.write_text(SAMPLE_XML)
    fake_result = MagicMock(returncode=0)

    with patch('phases.scan.tools.nmap_tool.shutil.which', return_value='/usr/bin/nmap'), \
         patch('phases.scan.tools.nmap_tool.subprocess.run', return_value=fake_result) as mock_run:
        NmapTool.fingerprint(
            '192.0.2.10', [22], xml_output_path=str(xml_path),
            extra_args=['--script', 'vulners', '--script-args', 'mincvss=7.0'],
        )

    command = mock_run.call_args[0][0]
    assert '--script' in command
    assert 'vulners' in command
    assert 'mincvss=7.0' in command
