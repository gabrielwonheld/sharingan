import json
import subprocess

from model.host import Host
from model.service_model import ExploitMatch, Service, Vulnerability
from phases.base import PhaseModule
from phases.scan.tools.nmap_tool import NmapTool
from phases.scan.tools.rustscan_tool import RustscanTool
from phases.scan.tools.searchsploit_tool import SearchsploitTool
from phases.scan.tools.vulners_tool import VulnersTool


class ScanPhase(PhaseModule):
    """Scan phase: port discovery + service fingerprinting + vulnerability/exploit correlation.

    Orchestrates external tools instead of reimplementing a scanner:
    RustscanTool (fast port discovery) -> NmapTool (`-sV`, product/version
    fingerprint on the discovered ports, embedding the `vulners` script when
    available) -> VulnersTool (reads CVE/CVSS from the same XML, matching by
    CPE — more precise than text search) -> SearchsploitTool (matches
    product/version against exploit-db from the nmap XML, only when vulners
    found something relevant, or always when vulners isn't installed). The
    result is persisted as `Service`, `Vulnerability` and `ExploitMatch`
    linked to the Host.
    """

    name = 'scan'
    description = (
        'Discovers open ports (rustscan), fingerprints service/version (nmap -sV), '
        'matches CVE/CVSS by CPE (vulners) and cross-references exploit-db (searchsploit).'
    )

    def __init__(
        self,
        db_session,
        rustscan=RustscanTool,
        nmap=NmapTool,
        vulners=VulnersTool,
        searchsploit=SearchsploitTool,
        xml_output_path='/tmp/sharingan_nmap_scan.xml',
        min_cvss=7.0,
    ):
        self.session = db_session
        self.rustscan = rustscan
        self.nmap = nmap
        self.vulners = vulners
        self.searchsploit = searchsploit
        self.xml_output_path = xml_output_path
        self.min_cvss = min_cvss

        # State from the last `run()` — the console uses this to know whether a
        # step (vulners/searchsploit) actually ran and found nothing, or never
        # ran at all (unavailable, or skipped because nothing relevant was
        # found). Without this there's no way to tell those two cases apart
        # when deciding whether to show a "nothing found" message.
        self.last_vulners_enabled: bool | None = None
        self.last_searchsploit_ran: bool | None = None
        # Only set when searchsploit was available (is_available() == True) but
        # failed at runtime (e.g. xmllint disappeared after the check, or any
        # other process failure) — distinct from "didn't run by design".
        self.last_searchsploit_error: str | None = None

    def run(self, name: str, target: str, on_progress=None) -> Host:
        """Runs the whole phase. `on_progress`, if given, is called with a string
        describing each step right before it actually runs — so the caller (the
        console) can show progress instead of a single static message sitting
        there until the whole scan finishes."""

        def notify(step: str) -> None:
            if on_progress:
                on_progress(step)

        self.last_searchsploit_error = None
        host = self._get_or_create_host(name, target)
        # A new scan is the host's most current snapshot — clear the previous
        # scan's result before persisting the new one, otherwise every run
        # duplicates `Service`/`Vulnerability`/`ExploitMatch` instead of
        # replacing them.
        self._clear_previous_scan_data(host)

        notify('Scanning open ports (rustscan)...')
        open_ports = self.rustscan.scan_ports(target)
        if not open_ports:
            host.ports_active = '[]'
            self.session.add(host)
            self.session.commit()
            self.last_vulners_enabled = False
            self.last_searchsploit_ran = False
            return host

        vulners_enabled = self.vulners.is_available()
        extra_args = self.vulners.build_nmap_args(self.min_cvss) if vulners_enabled else None

        # vulners isn't really a separate step — the script runs embedded in
        # this same nmap call (see `extra_args`), so the message reflects that
        # instead of announcing a step that doesn't exist as a separate process.
        nmap_step = 'Fingerprinting services and versions (nmap -sV)...'
        if vulners_enabled:
            nmap_step = 'Fingerprinting services and versions, with CVE/CVSS correlation (nmap -sV + vulners)...'
        notify(nmap_step)

        fingerprints = self.nmap.fingerprint(target, open_ports, self.xml_output_path, extra_args=extra_args)
        self._persist_services(host, fingerprints)

        # No signal from vulners (not installed), preserve the previous
        # behavior: try searchsploit whenever it's itself available.
        should_run_searchsploit = True

        if vulners_enabled:
            vulnerabilities = self.vulners.parse_xml(self.xml_output_path)
            self._persist_vulnerabilities(host, vulnerabilities)
            # With vulners available, searchsploit is only worth running if
            # there's something relevant (CVSS >= min_cvss) — avoids noise/
            # wasted time for nothing.
            should_run_searchsploit = bool(vulnerabilities)

        attempt_searchsploit = should_run_searchsploit and self.searchsploit.is_available()
        searchsploit_ran = False
        if attempt_searchsploit:
            notify('Looking up matching exploits (searchsploit)...')
            try:
                matches = self.searchsploit.search_nmap_xml(self.xml_output_path)
                self._persist_exploit_matches(host, matches)
                searchsploit_ran = True
            except subprocess.CalledProcessError as e:
                # searchsploit is optional/best-effort — a runtime failure
                # (e.g. missing xmllint, corrupted output, etc.) can't take
                # down the rest of the scan and throw away the nmap
                # fingerprint that was already persisted above.
                self.last_searchsploit_error = str(e)

        self.last_vulners_enabled = vulners_enabled
        self.last_searchsploit_ran = searchsploit_ran

        return host

    def _get_or_create_host(self, name: str, addr: str) -> Host:
        host = self.session.query(Host).filter_by(addr=addr).first()
        if not host:
            host = Host(nome=name, addr=addr)
            self.session.add(host)
            self.session.commit()
        return host

    def _clear_previous_scan_data(self, host: Host) -> None:
        """Deletes the previous scan's snapshot for this host before persisting
        the new one.

        Without this, running `scan` again on the same host would just keep
        stacking `Service` rows (and, in cascade, `Vulnerability`/
        `ExploitMatch`) — every run doubling what was already there, instead of
        the latest scan reflecting the host's current state. Since
        `Service.host` has `cascade='all, delete-orphan'` (and the same applies
        to `Vulnerability`/`ExploitMatch` on `Service`), deleting the `Service`
        rows already cascades — no need to delete `Vulnerability`/
        `ExploitMatch` separately here.
        """
        old_services = self.session.query(Service).filter_by(host_id=host.id).all()
        for service in old_services:
            self.session.delete(service)
        if old_services:
            self.session.commit()

    def _persist_services(self, host: Host, fingerprints) -> None:
        active_ports = []
        for fingerprint in fingerprints:
            service = Service(
                host_id=host.id,
                port=fingerprint.port,
                protocol=fingerprint.protocol,
                state=fingerprint.state,
                product=fingerprint.product,
                version=fingerprint.version,
                banner=fingerprint.banner,
                name=fingerprint.name,
            )
            self.session.add(service)
            if fingerprint.state == 'open':
                active_ports.append(fingerprint.port)

        host.ports_active = json.dumps(sorted(active_ports))
        self.session.commit()

    def _persist_vulnerabilities(self, host: Host, vulnerabilities) -> None:
        services_by_port = {
            service.port: service
            for service in self.session.query(Service).filter_by(host_id=host.id).all()
        }

        for vuln in vulnerabilities:
            service = services_by_port.get(vuln.port)
            if service is None:
                continue
            self.session.add(Vulnerability(
                service_id=service.id,
                cve=vuln.cve,
                cvss=vuln.cvss,
                reference=vuln.reference,
            ))

        self.session.commit()

    def _persist_exploit_matches(self, host: Host, matches: list[dict]) -> None:
        # Simple association for now: links every exploit found to the host's
        # first service. `searchsploit --nmap` doesn't return the originating
        # port directly; refining this (matching by product/version) is a next
        # step for when we want accurate multi-service-per-host support.
        services = self.session.query(Service).filter_by(host_id=host.id).all()
        if not services:
            return

        default_service = services[0]

        for match in matches:
            exploit = ExploitMatch(
                service_id=default_service.id,
                title=match.get('Title', 'unknown'),
                edb_id=str(match['EDB-ID']) if match.get('EDB-ID') else None,
                path=match.get('Path'),
            )
            self.session.add(exploit)

        self.session.commit()
