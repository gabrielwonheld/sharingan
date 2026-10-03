from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import backref, relationship
from datetime import datetime
from db.extensions import Base

class WhoisRecord(Base):
    __tablename__ = 'whois_records'
    
    id = Column(Integer, primary_key=True)
    # Nullable: records created before the Recon phase owned `whois` have no host.
    host_id = Column(Integer, ForeignKey('hosts.id'), nullable=True)
    domain = Column(String(255), nullable=False)
    raw_data = Column(Text, nullable=True)
    registrar = Column(String(255), nullable=True)
    creation_date = Column(DateTime, nullable=True)
    expiration_date = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    host = relationship('Host', backref=backref('whois_records', cascade='all, delete-orphan'))
