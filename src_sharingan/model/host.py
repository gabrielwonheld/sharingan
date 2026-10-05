from sqlalchemy import Column, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import backref, relationship

from db.extensions import Base
from model.workspace_model import DEFAULT_WORKSPACE_ID, Workspace  # noqa: F401  (Workspace: registers the model)


class Host(Base):
    __tablename__ = 'hosts'
    # A host is identified by its address *within a workspace*: the same address
    # can exist once per workspace, never twice in the same one.
    __table_args__ = (UniqueConstraint('workspace_id', 'addr', name='uq_host_workspace_addr'),)

    id = Column(Integer, primary_key=True)
    workspace_id = Column(Integer, ForeignKey('workspaces.id'), nullable=False, default=DEFAULT_WORKSPACE_ID)
    # A free-form label, not an identity: `addr` identifies the host. It used to be
    # UNIQUE, which made `scan <name> <addr>` fail whenever the same name was
    # reused for another address.
    nome = Column(String(80), nullable=False)
    addr = Column(String(120), nullable=False)
    ports_active = Column(String(120), unique=False, nullable=True)
    ports_inactive = Column(String(120), unique=False, nullable=True)
    subdomains = Column(String(120), unique=False, nullable=True)

    workspace = relationship('Workspace', backref=backref('hosts', cascade='all, delete-orphan'))
