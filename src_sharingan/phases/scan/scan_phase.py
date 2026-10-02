import json
import subprocess
from datetime import datetime, timezone

from model.host import Host
from model.service_model import ExploitMatch, ScanRun, Service, Vulnerability
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
    CPE — more precise than text search) -> SearchsploitTool (one search per
    fingerprinted service/product, only when vulners found something
    relevant, or always when vulners isn't installed). The result is
    persisted as `Service`, `Vulnerability` and `ExploitMatch` linked to the
    Host — each `ExploitMatch` tied to the exact `Service` it was searched
    for, not just "the host's first service".
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
        # The ScanRun created by the last `run()` (None before the first run).
        self.last_scan_run: ScanRun | None = None

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
        # Every scan is its own ScanRun: its services/vulnerabilities/exploits
        # belong to that run, and previous runs stay in the database as history
        # (the "current" view of a host is just its latest run — see
        # `current_services_filter`), instead of being wiped on every scan.
        run = ScanRun(host_id=host.id)
        self.session.add(run)
        self.session.commit()
        self.last_scan_run = run

        try:
            self._run_steps(host, run, target, notify)
        except Exception:
            # A failed flush leaves the session unusable until rolled back.
            self.session.rollback()
            # An interrupted scan must not be mistaken for a complete one (it
            # would look like ports "closed" and break any diff against it).
            self._finish_run(run, 'failed')
            raise
        self._finish_run(run, 'ok')
        return host

    def _finish_run(self, run: ScanRun, status: str) -> None:
        run.status = status
        run.finished_at = datetime.now(timezone.utc)
        self.session.add(run)
        self.session.commit()

    def _run_steps(self, host: Host, run: ScanRun, target: str, notify) -> None:
        notify('Scanning open ports (rustscan)...')
        open_ports = self.rustscan.scan_ports(target)
        if not open_ports:
            host.ports_active = '[]'
            self.session.add(host)
            self.session.commit()
            self.last_vulners_enabled = False
            self.last_searchsploit_ran = False
            return

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
        self._persist_services(host, run, fingerprints)

        # No signal from vulners (not installed), preserve the previous
        # behavior: try searchsploit whenever it's itself available.
        should_run_searchsploit = True

        if vulners_enabled:
            vulnerabilities = self.vulners.parse_xml(self.xml_output_path)
            self._persist_vulnerabilities(run, vulnerabilities)
            # With vulners available, searchsploit is only worth running if
            # there's something relevant (CVSS >= min_cvss) — avoids noise/
            # wasted time for nothing.
            should_run_searchsploit = bool(vulnerabilities)

        attempt_searchsploit = should_run_searchsploit and self.searchsploit.is_available()
        searchsploit_ran = False
        if attempt_searchsploit:
            notify('Looking up matching exploits (searchsploit)...')
            try:
                services = self.session.query(Service).filter_by(scan_run_id=run.id).all()
                matches_by_service = {}
                for service in services:
                    full_term = service.product or service.name
                    # "unknown" is nmap's own literal placeholder for "I
                    # couldn't identify this at all" (XML `<service
                    # name="unknown">`) — not a real product name. Searching
                    # it verbatim matched unrelated exploits whose titles
                    # happen to contain the word "Unknown" (confirmed during
                    # manual verification: LibTIFF, a Windows COM privilege
                    # escalation, a Firefox/Safari one, for a port that
                    # turned out to just be an unrelated local process).
                    if not full_term or full_term.lower() == 'unknown':
                        continue
                    # Only the first word: confirmed empirically that
                    # `searchsploit -t` requires every word supplied to
                    # appear (whole-word, not substring) in the title, and
                    # nmap's own `product` field is often a multi-word
                    # descriptive string ("Redis key-value store",
                    # "PostgreSQL DB") that exploit-db titles never fully
                    # contain — e.g. `-t "Redis key-value store"` finds
                    # nothing where `-t redis` finds 5 real matches.
                    term = full_term.split()[0]
                    matches_by_service[service] = self.searchsploit.search_product(term)
                self._persist_exploit_matches(matches_by_service)
                searchsploit_ran = True
            except subprocess.CalledProcessError as e:
                # searchsploit is optional/best-effort — a runtime failure
                # can't take down the rest of the scan and throw away the
                # nmap fingerprint that was already persisted above.
                self.last_searchsploit_error = str(e)

        self.last_vulners_enabled = vulners_enabled
        self.last_searchsploit_ran = searchsploit_ran

    def _get_or_create_host(self, name: str, addr: str) -> Host:
        host = self.session.query(Host).filter_by(addr=addr).first()
        if not host:
            host = Host(nome=name, addr=addr)
            self.session.add(host)
            self.session.commit()
        return host

    def _persist_services(self, host: Host, run: ScanRun, fingerprints) -> None:
        active_ports = []
        for fingerprint in fingerprints:
            service = Service(
                host_id=host.id,
                scan_run_id=run.id,
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

    def _persist_vulnerabilities(self, run: ScanRun, vulnerabilities) -> None:
        services_by_port = {
            service.port: service
            for service in self.session.query(Service).filter_by(scan_run_id=run.id).all()
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

    def _persist_exploit_matches(self, matches_by_service: dict) -> None:
        # Each service was searched individually (by its own product/name),
        # so the association is exact — no more "every exploit goes to the
        # host's first service" approximation.
        for service, matches in matches_by_service.items():
            for match in matches:
                exploit = ExploitMatch(
                    service_id=service.id,
                    title=match.get('Title', 'unknown'),
                    edb_id=str(match['EDB-ID']) if match.get('EDB-ID') else None,
                    path=match.get('Path'),
                    cve_codes=match.get('Codes') or None,
                    verified=match.get('Verified') == '1',
                )
                self.session.add(exploit)

        self.session.commit()
