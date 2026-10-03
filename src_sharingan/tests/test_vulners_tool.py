from unittest.mock import MagicMock, patch

from phases.scan.tools.vulners_tool import VulnersTool

SAMPLE_XML_WITH_VULNERS = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
        <script id="vulners" output="&#10;cpe:/a:openbsd:openssh:8.9p1:&#10;\tCVE-2023-9999\t9.8\thttps://vulners.com/cve/CVE-2023-9999&#10;\tCVE-2022-1111\t7.5\thttps://vulners.com/cve/CVE-2022-1111&#10;"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

SAMPLE_XML_WITHOUT_VULNERS = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_is_available_false_when_nmap_missing():
    with patch('phases.scan.tools.vulners_tool.shutil.which', return_value=None):
        assert VulnersTool.is_available() is False


def test_is_available_checks_script_help_exit_code():
    fake_result = MagicMock(returncode=0)
    with patch('phases.scan.tools.vulners_tool.shutil.which', return_value='/usr/bin/nmap'), \
         patch('phases.scan.tools.vulners_tool.subprocess.run', return_value=fake_result) as mock_run:
        assert VulnersTool.is_available() is True

    assert mock_run.call_args[0][0] == ['nmap', '--script-help', 'vulners']


def test_is_available_false_when_script_help_fails():
    fake_result = MagicMock(returncode=1)
    with patch('phases.scan.tools.vulners_tool.shutil.which', return_value='/usr/bin/nmap'), \
         patch('phases.scan.tools.vulners_tool.subprocess.run', return_value=fake_result):
        assert VulnersTool.is_available() is False


def test_build_nmap_args_includes_mincvss():
    assert VulnersTool.build_nmap_args(min_cvss=7.0) == [
        '--script', 'vulners', '--script-args', 'mincvss=7.0',
    ]


def test_parse_xml_extracts_cve_matches_per_port(tmp_path):
    xml_path = tmp_path / 'scan.xml'
    xml_path.write_text(SAMPLE_XML_WITH_VULNERS)

    matches = VulnersTool.parse_xml(str(xml_path))

    assert len(matches) == 2
    high = next(m for m in matches if m.cve == 'CVE-2023-9999')
    assert high.port == 22
    assert high.cvss == 9.8
    assert 'vulners.com' in high.reference

    other = next(m for m in matches if m.cve == 'CVE-2022-1111')
    assert other.port == 22
    assert other.cvss == 7.5


def test_parse_xml_returns_empty_when_no_vulners_script(tmp_path):
    xml_path = tmp_path / 'scan.xml'
    xml_path.write_text(SAMPLE_XML_WITHOUT_VULNERS)

    assert VulnersTool.parse_xml(str(xml_path)) == []
