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
		
       
        HOSTS = Host.read_yaml_host()
       

        monit = Monit(HOSTS)
        #print(HOSTS, PORT)

        try:
            
            
            while True:  
                
                
                #monit.get_active()
                
                monit.get_inactive()
                   
                
                sleep(5)
                
                
    
        except KeyboardInterrupt:
            print("\nRecebido sinal de interrupção (Ctrl+C). Saindo...")
            sys.exit(1)
    