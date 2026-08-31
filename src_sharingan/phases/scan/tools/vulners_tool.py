import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass


@dataclass
class VulnerabilityMatch:
    port: int
    cve: str
    cvss: float
    reference: str


class VulnersTool:
    """Wrapper around the `vulners` NSE script (runs inside `nmap -sV` itself).

    Unlike rustscan/nmap/searchsploit, this isn't a separate binary — it's a
    script that needs to be installed in nmap's script folder (official
    repository `vulnersCom/nmap-vulners`). It uses the CPE that `-sV` already
    identifies to query the vulners.com API and returns CVE + CVSS ranked by
    severity — more precise than matching by text (like `searchsploit --nmap`
    does), because it matches on the structured identifier (CPE) rather than
    words from the product title.

    `is_available()` checks whether the script is installed via
    `nmap --script-help vulners` (nmap exits with a non-zero code when it
    can't find the script).
    """

    binary = 'nmap'
    script_name = 'vulners'

    @classmethod
    def is_available(cls) -> bool:
        if shutil.which(cls.binary) is None:
            return False

        try:
            result = subprocess.run(
                [cls.binary, '--script-help', cls.script_name],
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            return False

        return result.returncode == 0

    @classmethod
    def build_nmap_args(cls, min_cvss: float = 7.0) -> list[str]:
        """Extra arguments to embed in NmapTool's command — doesn't run nmap on its own."""
        return ['--script', cls.script_name, '--script-args', f'mincvss={min_cvss}']

    @classmethod
    def parse_xml(cls, xml_path: str) -> list[VulnerabilityMatch]:
        """Reads the same XML NmapTool already generated and extracts the vulners script's matches."""
        tree = ET.parse(xml_path)
        root = tree.getroot()

        matches: list[VulnerabilityMatch] = []
        for host in root.findall('host'):
            ports_el = host.find('ports')
            if ports_el is None:
                continue

            for port_el in ports_el.findall('port'):
                port_num = int(port_el.get('portid'))
                for script_el in port_el.findall('script'):
                    if script_el.get('id') != cls.script_name:
                        continue
                    output = script_el.get('output', '')
                    matches.extend(cls._parse_script_output(port_num, output))

        return matches

    _LINE_PATTERN = re.compile(r'(CVE-\d{4}-\d+)\s+([\d.]+)\s+(\S+)')

    @classmethod
    def _parse_script_output(cls, port: int, output: str) -> list[VulnerabilityMatch]:
        """Each relevant line of the vulners script's output has the format
        `CVE-2012-1667\t8.5\thttps://vulners.com/cve/CVE-2012-1667`."""
        matches = []
        for line in output.splitlines():
            m = cls._LINE_PATTERN.search(line.strip())
            if m:
                cve, cvss, reference = m.groups()
                matches.append(VulnerabilityMatch(port=port, cve=cve, cvss=float(cvss), reference=reference))
        return matches
