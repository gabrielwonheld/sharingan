from sqlalchemy import Column, Integer, String, Text, DateTime
from datetime import datetime
from db.extensions import Base

class WhoisRecord(Base):
    __tablename__ = 'whois_records'
    
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), nullable=False)
    raw_data = Column(Text, nullable=True)
    registrar = Column(String(255), nullable=True)
    creation_date = Column(DateTime, nullable=True)
    expiration_date = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
