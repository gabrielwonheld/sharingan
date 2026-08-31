import sys
from time import sleep

from core.monitor_core import Monit
from utils.host_processor_utils import Host
from utils.validation_utils import Validation
from view.display import MonitDisplay


class Monitor_Service:
    
    def __init__(self, hosts_file):
        Validation.validationArgs()
        self.HOSTS = Host.read_yaml_host(
            hosts_file
        )  # Passes the hosts file
        self.monit = Monit(self.HOSTS)
        self.display = MonitDisplay()

    def get_active(self):
        try:
            while True:
                hosts = self.monit.get_hosts()

                self.display.display_active(hosts)
                sleep(5)
        except KeyboardInterrupt:
            print('\nReceived interrupt signal (Ctrl+C). Exiting...')
            sys.exit(1)

    def get_inactive(self):
        try:
            while True:
                hosts = self.monit.get_hosts()

                self.display.display_inactive(hosts)

                sleep(5)
        except KeyboardInterrupt:
            print('\nReceived interrupt signal (Ctrl+C). Exiting...')
            sys.exit(1)
