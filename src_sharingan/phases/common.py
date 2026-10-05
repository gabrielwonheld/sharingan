from model.host import Host
from model.workspace_model import DEFAULT_WORKSPACE_ID


def get_or_create_host(session, name: str, addr: str, workspace_id: int = DEFAULT_WORKSPACE_ID) -> Host:
    """Shared by every phase that needs a Host for a target: reuses the existing
    row by address within the workspace (the host's real identity — see
    model/host.py) or creates one. Extracted so the phases don't each
    reimplement it."""
    host = session.query(Host).filter_by(workspace_id=workspace_id, addr=addr).first()
    if not host:
        host = Host(nome=name, addr=addr, workspace_id=workspace_id)
        session.add(host)
        session.commit()
    return host
