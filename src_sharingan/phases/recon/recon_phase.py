from model.host import Host
from model.subdomain_model import Subdomain
from phases.base import PhaseModule
from phases.common import get_or_create_host
from phases.recon.tools.subfinder_tool import SubfinderTool


class ReconPhase(PhaseModule):
    """Recon phase: passive subdomain discovery via subfinder.

    Results are deduplicated and persisted linked to the Host (the same
    entity the Scan phase uses, reused by address — scanning and reconning
    the same domain share one Host row). Subdomains already known from a
    previous run are kept, not re-inserted; `last_new_subdomains` records
    which ones are new on *this* run, so the console can highlight them —
    the same "what changed" signal `ScanRun`/`scan diff` already give the
    Scan phase.
    """

    name = 'recon'
    description = 'Discovers subdomains of a domain via passive sources (subfinder).'

    def __init__(self, db_session, subfinder=SubfinderTool):
        self.session = db_session
        self.subfinder = subfinder
        self.last_new_subdomains: list[str] = []
        self.last_all_subdomains: list[str] = []

    def run(self, name: str, domain: str) -> Host:
        host = get_or_create_host(self.session, name, domain)
        found = self.subfinder.find_subdomains(domain)

        existing = {s.name for s in self.session.query(Subdomain).filter_by(host_id=host.id)}
        new_names = sorted(n for n in found if n not in existing)
        for subdomain_name in new_names:
            self.session.add(Subdomain(host_id=host.id, name=subdomain_name))
        if new_names:
            self.session.commit()

        self.last_new_subdomains = new_names
        self.last_all_subdomains = sorted(existing | set(found))
        return host
