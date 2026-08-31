from sqlalchemy import Column, Integer, String
from db.extensions import Base

class Host(Base):
    __tablename__ = 'hosts'
    
    id = Column(Integer, primary_key=True)
    nome = Column(String(80), unique=True, nullable=False)
    addr = Column(String(120), unique=True, nullable=False)
    ports_active = Column(String(120), unique=False, nullable=True)
    ports_inactive = Column(String(120), unique=False, nullable=True)
    subdomains = Column(String(120), unique=False, nullable=True)
