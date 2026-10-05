from urllib.parse import urlparse

from model.finding_model import Finding
from model.host import Host
from model.workspace_model import DEFAULT_WORKSPACE_ID
from phases.base import PhaseModule
from phases.common import get_or_create_host
from phases.fuzz.tools.gobuster_tool import GobusterTool


class FuzzPhase(PhaseModule):
    """Fuzz phase: directory/file enumeration against a web target (gobuster).

    Unlike Scan/Recon, this sends a real, sizeable volume of HTTP requests to
    the target — active enumeration, not passive recon or a bounded port
    sweep. The console checks scope on the URL's hostname **before** this
    phase ever runs (`_target_allowed_by_scope`, the same helper `scan` and
    `recon` use), and it's its own opt-in command — never run automatically
    as part of `scan`.

    Findings already known from a previous `fuzz` run against the same host
    and base URL are kept, not re-inserted; `last_new_paths` records which
    ones are new on *this* run — the same "what changed" signal `recon`'s
    `last_new_subdomains` already gives.
    """

    name = 'fuzz'
    description = 'Directory/file enumeration against a web target (gobuster).'

    def __init__(self, db_session, gobuster=GobusterTool, workspace_id=DEFAULT_WORKSPACE_ID):
        self.session = db_session
        self.workspace_id = workspace_id
        self.gobuster = gobuster
        self.last_new_paths: list[str] = []
        self.last_all_matches: list = []

    def run(
        self,
        name: str,
        url: str,
        wordlist: str,
        extensions: str | None = None,
        threads: int = 10,
        status_codes: str | None = None,
        on_progress=None,
    ) -> Host:
        """`on_progress`, if given, is called with a string naming the actual
        command about to run — mirrors `ScanPhase.run`/`ReconPhase.run`."""
        if on_progress:
            on_progress(f'Enumerating directories/files (gobuster dir -u {url})...')

        hostname = urlparse(url).hostname or url
        host = get_or_create_host(self.session, name, hostname, self.workspace_id)

        matches = self.gobuster.enumerate(
            url, wordlist, extensions=extensions, threads=threads, status_codes=status_codes,
        )

        existing_paths = {
            f.path for f in self.session.query(Finding).filter_by(host_id=host.id, url=url)
        }
        new_matches = [m for m in matches if m.path not in existing_paths]
        for match in new_matches:
            self.session.add(Finding(
                host_id=host.id,
                url=url,
                path=match.path,
                status_code=match.status_code,
                size=match.size,
                redirect=match.redirect,
            ))
        if new_matches:
            self.session.commit()

        self.last_new_paths = [m.path for m in new_matches]
        self.last_all_matches = matches
        return host
