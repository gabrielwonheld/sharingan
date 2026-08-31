from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.check_host_utils import check_host
from model.host import Host
import json

class AdvancedMonitorService:
    def __init__(self, db_session):
        self.session = db_session

    def scan_ports(self, name: str, ip: str, ports: list[int], max_workers: int = 10) -> Host:
        active_ports = []
        inactive_ports = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(check_host, name, ip, port): port
                for port in ports
            }
            
            for future in as_completed(futures):
                _, _, port, is_active = future.result()
                if is_active:
                    active_ports.append(port)
                else:
                    inactive_ports.append(port)
                    
        # Fetch or create the Host in the database
        host = self.session.query(Host).filter_by(addr=ip).first()
        if not host:
            host = Host(nome=name, addr=ip)
        else:
            # In case there were ports already stored in the DB as JSON:
            pass
            
        host.ports_active = json.dumps(active_ports)
        host.ports_inactive = json.dumps(inactive_ports)
        
        self.session.add(host)
        self.session.commit()
        return host
