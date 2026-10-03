from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import backref, relationship

from db.extensions import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CrawledPage(Base):
    """A URL visited by the web crawler (`crawl`), tied to a Host.

    Unique per `(host_id, url)` so re-running `crawl` doesn't duplicate pages
    already known — same idea as `Finding` and `Subdomain`.
    """

    __tablename__ = 'crawled_pages'
    __table_args__ = (UniqueConstraint('host_id', 'url', name='uq_crawled_page_host_url'),)

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey('hosts.id'), nullable=False)
    url = Column(String(2048), nullable=False)
    status_code = Column(Integer, nullable=True)
    depth = Column(Integer, nullable=False, default=0)
    discovered_at = Column(DateTime, nullable=False, default=_utcnow)

    host = relationship('Host', backref=backref('crawled_pages', cascade='all, delete-orphan'))


class HarvestedEmail(Base):
    """An email address found while crawling, with the first page it appeared on."""

    __tablename__ = 'harvested_emails'
    __table_args__ = (UniqueConstraint('host_id', 'email', name='uq_harvested_email_host_email'),)

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey('hosts.id'), nullable=False)
    email = Column(String(255), nullable=False)
    source_url = Column(String(2048), nullable=True)
    discovered_at = Column(DateTime, nullable=False, default=_utcnow)

    host = relationship('Host', backref=backref('harvested_emails', cascade='all, delete-orphan'))
