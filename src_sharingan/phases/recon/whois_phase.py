from model.whois_model import WhoisRecord
from model.workspace_model import DEFAULT_WORKSPACE_ID
from phases.base import PhaseModule
from phases.common import get_or_create_host
from services.whois_service import WhoisService


class WhoisPhase(PhaseModule):
    """Recon phase: WHOIS lookup of a domain (python-whois).

    The record is linked to the Host of that domain — the same row `scan` and
    `recon` use, reused by address — so `hosts -d` cleans it up too. Each run
    stores a new record, so registrar/expiry changes stay visible over time.
    Like `recon`, it only talks to public WHOIS servers, never to the target.
    """

    name = 'whois'
    description = 'WHOIS lookup of a domain, linked to its host.'

    def __init__(self, db_session, whois_service=WhoisService, workspace_id=DEFAULT_WORKSPACE_ID):
        self.session = db_session
        self.workspace_id = workspace_id
        self.whois_service = whois_service

    def run(self, domain: str, on_progress=None) -> WhoisRecord:
        """`on_progress`, if given, is called before the lookup — mirrors `ReconPhase.run`."""
        if on_progress:
            on_progress(f'Querying WHOIS for {domain}...')

        host = get_or_create_host(self.session, domain, domain, self.workspace_id)
        return self.whois_service(self.session).perform_whois(domain, host_id=host.id)
