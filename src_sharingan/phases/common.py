from model.host import Host


def get_or_create_host(session, name: str, addr: str) -> Host:
    """Shared by every phase that needs a Host for a target: reuses the existing
    row by address (the host's real identity — see model/host.py) or creates
    one. Extracted so ScanPhase and ReconPhase don't each reimplement it."""
    host = session.query(Host).filter_by(addr=addr).first()
    if not host:
        host = Host(nome=name, addr=addr)
        session.add(host)
        session.commit()
    return host
