import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.cli import Cli
from utils.check_host_utils import check_host
from utils.clear_utils import Clean
from view.banner import Banner
from view.display import MonitDisplay

args = Cli.parse_args()
lock = threading.Lock()


class Monit:
    def __init__(self, HOST):

        self.host = HOST

        self.list_active_host = []
        self.list_inactive_host = []
        self.list_total_host = []

        self.dic_previous_active_host = {}
        self.dic_previous_inactive_host = {}

        self.dic_active_host = {}
        self.dic_active_port_host = {}
        self.dic_active_addr_host = {}

        self.dic_inactive_host = {}
        self.dic_inactive_port_host = {}
        self.dic_inactive_addr_host = {}

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
            self.list_total_host.append(f'{nome}:{port}')

            if status:

                if nome not in self.dic_active_port_host:
                    self.dic_active_port_host[nome] = []
                self.dic_active_port_host[nome].append(port)

                # Organiza as portas em ordem crescente
                self.dic_active_port_host[nome] = sorted(
                    self.dic_active_port_host[nome]
                )
                self.dic_active_addr_host[nome] = addr

            if not status:

                if nome not in self.dic_inactive_port_host:
                    self.dic_inactive_port_host[nome] = []
                self.dic_inactive_port_host[nome].append(port)

                # Organiza as portas em ordem crescente
                self.dic_inactive_port_host[nome] = sorted(
                    self.dic_inactive_port_host[nome]
                )
                self.dic_inactive_addr_host[nome] = addr

    def get_active(self):

        with lock:

            self.dic_active_port_host.clear()
            self.dic_active_addr_host.clear()
            Clean.clear_list(
                self.dic_active_addr_host, self.dic_active_port_host
            )

            self.separate_results()

            if self.dic_previous_active_host != self.dic_active_port_host:

                Clean.clear_terminal()
                Banner.sharingan()

                display_host = MonitDisplay(
                    active=self.dic_active_port_host,
                    total=self.list_total_host,
                )
                display_host.display_active()
                self.dic_previous_active_host = (
                    self.dic_active_port_host.copy()
                )

        return self.dic_previous_active_host

    def get_inactive(self):

        with lock:

            self.dic_inactive_port_host.clear()
            self.dic_inactive_addr_host.clear()
            Clean.clear_list(
                self.list_active_host,
                self.list_inactive_host,
                self.list_total_host,
            )

            self.separate_results()

            if self.dic_previous_inactive_host != self.dic_inactive_port_host:

                Clean.clear_terminal()
                Banner.sharingan()

                display_host = MonitDisplay(
                    inactive=self.dic_inactive_port_host,
                    total=self.list_total_host,
                )
                display_host.display_inactive()
                self.dic_previous_inactive_host = (
                    self.dic_inactive_port_host.copy()
                )

        return self.dic_previous_inactive_host
