import sys
from time import sleep

from core.monitor_core import Monit
from utils.host_processor_utils import Host
from utils.validation_utils import Validation


class Monitor_Service:
    def __init__(self, hosts_file):
        Validation.validationArgs()
        self.HOSTS = Host.read_yaml_host(
            hosts_file
        )  # Passa o arquivo de hosts
        self.monit = Monit(self.HOSTS)

    def get_active(self):
        try:
            while True:
                self.monit.get_active()
                sleep(5)
        except KeyboardInterrupt:
            print('\nRecebido sinal de interrupção (Ctrl+C). Saindo...')
            sys.exit(1)

    def get_inactive(self):
        try:
            while True:
                self.monit.get_inactive()
                sleep(5)
        except KeyboardInterrupt:
            print('\nRecebido sinal de interrupção (Ctrl+C). Saindo...')
            sys.exit(1)
