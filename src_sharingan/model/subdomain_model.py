from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import backref, relationship

from db.extensions import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Subdomain(Base):
    """A subdomain discovered by the Recon phase (passive sources via subfinder), tied to a Host.

    Named `subdomain_records` on the Host relationship, not `subdomains` —
    that name is already taken by `Host.subdomains`, a legacy free-text
    column (max 120 chars) that predates this structured table and isn't
    written to by this phase.
    """

    __tablename__ = 'subdomains'
    __table_args__ = (UniqueConstraint('host_id', 'name', name='uq_subdomain_host_name'),)

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey('hosts.id'), nullable=False)
    name = Column(String(255), nullable=False)
    discovered_at = Column(DateTime, nullable=False, default=_utcnow)

    host = relationship('Host', backref=backref('subdomain_records', cascade='all, delete-orphan'))
