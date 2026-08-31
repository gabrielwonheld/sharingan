from sqlalchemy import Column, Float, ForeignKey, Integer, String
from sqlalchemy.orm import backref, relationship

from db.extensions import Base


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

    # cascade='all, delete-orphan': deleting a Host deletes its Service rows too
    # — without this SQLAlchemy only nulls `host_id` (breaking the NOT NULL
    # constraint) instead of deleting, leaving orphaned rows in the database.
    # Required for the `hosts -d` / `services -d` console commands and so a
    # re-scan doesn't accumulate duplicate services.
    host = relationship('Host', backref=backref('services', cascade='all, delete-orphan'))


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

    service = relationship('Service', backref=backref('exploit_matches', cascade='all, delete-orphan'))
