from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, and_, func, or_, select
from sqlalchemy.orm import backref, relationship

from db.extensions import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanRun(Base):
    """One execution of the Scan phase against a Host.

    Groups the `Service` rows (and, through them, vulnerabilities and exploit
    matches) found by that specific execution, so a host can keep a history of
    scans instead of a single overwritten snapshot — the basis for diffing two
    scans and, later, for continuous monitoring.
    """

    __tablename__ = 'scan_runs'

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey('hosts.id'), nullable=False)
    started_at = Column(DateTime, nullable=False, default=_utcnow)
    finished_at = Column(DateTime, nullable=True)
    # 'running' until the phase finishes; later 'ok' / 'failed' / 'partial'. A
    # run that didn't finish must not be used as a baseline for a diff.
    status = Column(String(20), nullable=False, default='running')

    # cascade='all, delete-orphan': deleting a Host deletes its scan history.
    host = relationship('Host', backref=backref('scan_runs', cascade='all, delete-orphan'))


class Service(Base):
    """A service identified on a Host's port (result of the Scan phase).

    Exists as its own table (instead of reusing `Host.ports_active`) because
    correlating with the exploit-db needs product/version per port, not just
    the list of open ports.
    """

    __tablename__ = 'services'

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey('hosts.id'), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), default='tcp')
    state = Column(String(20), default='open')
    product = Column(String(120), nullable=True)
    version = Column(String(120), nullable=True)
    banner = Column(String(255), nullable=True)
    # nmap's own guess at the service (the XML `<service name="...">` attribute),
    # populated even when nmap -sV can't grab a banner (product/version stay None)
    # but still maps the port number against nmap-services. Kept separate from
    # `product` because it's a lower-confidence signal (can be a plain port-table
    # lookup, not an actual probe) — the console shows it only as a fallback.
    name = Column(String(120), nullable=True)
    # Which scan execution found this service. Nullable: rows created before
    # ScanRun existed have no run (legacy data).
    scan_run_id = Column(Integer, ForeignKey('scan_runs.id'), nullable=True)

    # cascade='all, delete-orphan': deleting a Host deletes its Service rows too
    # — without this SQLAlchemy only nulls `host_id` (breaking the NOT NULL
    # constraint) instead of deleting, leaving orphaned rows in the database.
    # Required for the `hosts -d` / `services -d` console commands and so a
    # re-scan doesn't accumulate duplicate services.
    host = relationship('Host', backref=backref('services', cascade='all, delete-orphan'))
    # Deleting a run deletes the services (and their CVEs/exploits) it found,
    # leaving the host's other runs untouched.
    scan_run = relationship('ScanRun', backref=backref('services', cascade='all, delete-orphan'))


class Vulnerability(Base):
    """A CVE (with CVSS) matched by CPE via the `vulners` NSE script, tied to a Service.

    Matches on the structured identifier (CPE) that `nmap -sV` already
    extracts — more precise than `searchsploit`'s text search. Depends on
    internet access (queries the vulners.com API); when the script isn't
    installed, this table simply stays empty and the scan phase carries on
    without it.
    """

    __tablename__ = 'vulnerabilities'

    id = Column(Integer, primary_key=True)
    service_id = Column(Integer, ForeignKey('services.id'), nullable=False)
    cve = Column(String(30), nullable=False)
    cvss = Column(Float, nullable=True)
    reference = Column(String(255), nullable=True)

    service = relationship('Service', backref=backref('vulnerabilities', cascade='all, delete-orphan'))


class ExploitMatch(Base):
    """An exploit-db entry (via searchsploit) tied to a Service."""

    __tablename__ = 'exploit_matches'

    id = Column(Integer, primary_key=True)
    service_id = Column(Integer, ForeignKey('services.id'), nullable=False)
    title = Column(String(255), nullable=False)
    edb_id = Column(String(20), nullable=True)
    path = Column(String(255), nullable=True)
    # exploit-db's own `Codes` field (e.g. "CVE-2008-3234;OSVDB-48791"), kept
    # so the console can cross-reference it against this service's own
    # `Vulnerability.cve` rows (already confirmed by vulners) without calling
    # searchsploit again — the main noise-reduction signal for a service with
    # many exploit-db hits but few (or zero) exact CVE matches.
    cve_codes = Column(String(255), nullable=True)
    # exploit-db's own "Verified" flag — used as a secondary sort key when
    # there's no CVE overlap to rank by.
    verified = Column(Boolean, nullable=True)

    service = relationship('Service', backref=backref('exploit_matches', cascade='all, delete-orphan'))


def current_services_filter():
    """SQL clause selecting each host's *current* services, for use in a `WHERE`.

    The current view of a host is its most recent scan run that didn't fail;
    older runs stay in the database as history but are not shown by default. A
    host with no runs at all (data from before `ScanRun` existed) keeps its
    legacy services (`scan_run_id IS NULL`) as current.

    Works inside joins across hosts, so callers just add it to their query.
    """
    latest_run_ids = (
        select(func.max(ScanRun.id))
        .where(ScanRun.status != 'failed')
        .group_by(ScanRun.host_id)
    )
    hosts_with_runs = select(ScanRun.host_id)
    return or_(
        Service.scan_run_id.in_(latest_run_ids),
        and_(Service.scan_run_id.is_(None), Service.host_id.not_in(hosts_with_runs)),
    )
