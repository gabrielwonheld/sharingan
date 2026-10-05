from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import backref, relationship

from db.extensions import Base
from model.workspace_model import DEFAULT_WORKSPACE_ID, Workspace  # noqa: F401  (Workspace: registers the model)


class ScopeRule(Base):
    """One line of a workspace's scope: what may (include) or may not (exclude) be scanned.

    `kind` is 'domain' (the domain and all its subdomains), 'ip' or 'cidr'.
    `value` is stored normalized (see `core.scope.parse_scope_value`) and is
    unique per workspace, so adding a value twice updates the existing rule —
    and each engagement keeps its own authorised targets.
    """

    __tablename__ = 'scope_rules'
    __table_args__ = (UniqueConstraint('workspace_id', 'value', name='uq_scope_workspace_value'),)

    id = Column(Integer, primary_key=True)
    workspace_id = Column(Integer, ForeignKey('workspaces.id'), nullable=False, default=DEFAULT_WORKSPACE_ID)
    kind = Column(String(10), nullable=False)
    value = Column(String(255), nullable=False)
    allow = Column(Boolean, nullable=False, default=True)

    workspace = relationship('Workspace', backref=backref('scope_rules', cascade='all, delete-orphan'))
