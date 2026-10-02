from sqlalchemy import Column, Integer, String
from db.extensions import Base

class Host(Base):
    __tablename__ = 'hosts'
    
    id = Column(Integer, primary_key=True)
    # A free-form label, not an identity: `addr` identifies the host. It used to be
    # UNIQUE, which made `scan <name> <addr>` fail whenever the same name was
    # reused for another address.
    nome = Column(String(80), nullable=False)
    addr = Column(String(120), unique=True, nullable=False)
    ports_active = Column(String(120), unique=False, nullable=True)
    ports_inactive = Column(String(120), unique=False, nullable=True)
    subdomains = Column(String(120), unique=False, nullable=True)
