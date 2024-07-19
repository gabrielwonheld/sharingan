from utils.validation_utils import Validation
from utils.clear_utils import Clean
from core.monitor_core import Monit
from services.host_processor_service import Host
from view.banner import Banner

from time import sleep
import sys


class Monitor_Service():

    @staticmethod
    def run_monitor():
        
        Validation.validationArgs()
		
       
        HOSTS, PORT = Host.read_yaml_host()
       

        monit = Monit(HOSTS,PORT)

        try:
            
            while True:
                Banner.sharingan()
                monit.get_active()
                #monit.get_inactive()
                

    
                
                Clean.clear_list(monit.list_inactive_host,monit.list_active_host,monit.list_total_host) #ao terminar o loop ira apagar as listas de monitor_core.Monit()
                sleep(5)
                Clean.clear_terminal()
                
    
        except KeyboardInterrupt:
            print("\nRecebido sinal de interrupção (Ctrl+C). Saindo...")
            sys.exit(1)
    