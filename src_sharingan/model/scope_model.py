from sqlalchemy import Boolean, Column, Integer, String

from db.extensions import Base


class ScopeRule(Base):
    """One line of the engagement scope: what may (include) or may not (exclude) be scanned.

    `kind` is 'domain' (the domain and all its subdomains), 'ip' or 'cidr'.
    `value` is stored normalized (see `core.scope.parse_scope_value`) and is
    unique, so adding a value twice updates the existing rule.
    """

    __tablename__ = 'scope_rules'

    id = Column(Integer, primary_key=True)
    kind = Column(String(10), nullable=False)
    value = Column(String(255), nullable=False, unique=True)
    allow = Column(Boolean, nullable=False, default=True)
