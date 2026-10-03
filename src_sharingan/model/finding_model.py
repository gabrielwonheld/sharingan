from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import backref, relationship

from db.extensions import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Finding(Base):
    """A path discovered by directory/file enumeration (the Fuzz phase: `gobuster dir`), tied to a Host.

    `url` is the base URL that run targeted (a Host can be fuzzed under more
    than one base URL — e.g. different ports or schemes); `path` is unique
    per `(host_id, url)` so re-running `fuzz` doesn't duplicate already-known
    findings, mirroring how `recon`'s `Subdomain` avoids duplicates.
    """

    __tablename__ = 'findings'
    __table_args__ = (UniqueConstraint('host_id', 'url', 'path', name='uq_finding_host_url_path'),)

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey('hosts.id'), nullable=False)
    url = Column(String(255), nullable=False)
    path = Column(String(255), nullable=False)
    status_code = Column(Integer, nullable=True)
    size = Column(Integer, nullable=True)
    redirect = Column(String(255), nullable=True)
    discovered_at = Column(DateTime, nullable=False, default=_utcnow)

    host = relationship('Host', backref=backref('findings', cascade='all, delete-orphan'))
