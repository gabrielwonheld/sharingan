from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String

from db.extensions import Base

# The workspace every pre-existing row belongs to, and the one the console
# starts in. `db/migrations.py` and `init_db()` make sure it exists with this id.
DEFAULT_WORKSPACE_ID = 1
DEFAULT_WORKSPACE_NAME = 'default'


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Workspace(Base):
    """A project/engagement: hosts (and with them every phase's results) and
    scope rules belong to exactly one workspace, so the same address can be
    worked on in two projects without their data mixing. Deleting a workspace
    deletes its hosts and scope rules (cascade), and through the hosts
    everything the phases saved.
    """

    __tablename__ = 'workspaces'

    id = Column(Integer, primary_key=True)
    name = Column(String(40), nullable=False, unique=True)
    created_at = Column(DateTime, nullable=False, default=_utcnow)
