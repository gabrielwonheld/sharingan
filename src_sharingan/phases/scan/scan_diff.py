from dataclasses import dataclass, field

from model.service_model import ScanRun, Service, Vulnerability


@dataclass
class ScanDiff:
    """What changed on a host between two scan runs (`old` -> `new`)."""

    opened: list[int] = field(default_factory=list)
    closed: list[int] = field(default_factory=list)
    # (port, old label, new label), e.g. (22, 'OpenSSH 8.9', 'OpenSSH 9.6')
    version_changed: list[tuple[int, str, str]] = field(default_factory=list)
    # (port, cve)
    new_cves: list[tuple[int, str]] = field(default_factory=list)
    resolved_cves: list[tuple[int, str]] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not (self.opened or self.closed or self.version_changed
                    or self.new_cves or self.resolved_cves)


def service_label(service: Service) -> str:
    return f"{service.product or service.name or '?'} {service.version or ''}".strip()


def _services_by_port(session, run: ScanRun) -> dict[int, Service]:
    return {s.port: s for s in session.query(Service).filter_by(scan_run_id=run.id)}


def _cves(session, run: ScanRun) -> set[tuple[int, str]]:
    rows = (
        session.query(Service.port, Vulnerability.cve)
        .join(Vulnerability, Vulnerability.service_id == Service.id)
        .filter(Service.scan_run_id == run.id)
    )
    return {(port, cve) for port, cve in rows}


def diff_scan_runs(session, old: ScanRun, new: ScanRun) -> ScanDiff:
    """Compares two runs of the same host. Pure read — never writes."""
    old_services = _services_by_port(session, old)
    new_services = _services_by_port(session, new)

    version_changed = [
        (port, service_label(old_services[port]), service_label(new_services[port]))
        for port in sorted(old_services.keys() & new_services.keys())
        if service_label(old_services[port]) != service_label(new_services[port])
    ]
    old_cves, new_cves = _cves(session, old), _cves(session, new)

    return ScanDiff(
        opened=sorted(new_services.keys() - old_services.keys()),
        closed=sorted(old_services.keys() - new_services.keys()),
        version_changed=version_changed,
        new_cves=sorted(new_cves - old_cves),
        resolved_cves=sorted(old_cves - new_cves),
    )
