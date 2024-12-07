import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.cli import Cli
from model.host import Host
from utils.check_host_utils import check_host
from utils.clear_utils import Clean
from view.banner import Banner
from view.display import MonitDisplay

args = Cli.parse_args()
lock = threading.Lock()


class Monit:
    def __init__(self, HOST):

        self.host = HOST

        self.hosts = {}

    def all_run_threads(self, func):
        results = []
        with ThreadPoolExecutor(max_workers=args.tasks) as executor:

            futures = {
                executor.submit(func, host, details['addr'], port): (
                    host,
                    port,
                )
                for host, details in self.host.items()
                for port in details['ports']
            }

            for future in as_completed(futures):
                result = future.result()
                results.append(result)
        return results

    def separate_results(self):
        results = self.all_run_threads(check_host)

        for nome, addr, port, status in results:

            if nome not in self.hosts.keys():

                self.hosts[nome] = Host(nome, addr)

            if status:

                self.hosts[nome].add_port_active(port)

            else:
                self.hosts[nome].add_port_inactive(port)

    def get_hosts(self):

        self.hosts.clear()
        self.separate_results()
        return self.hosts


        
