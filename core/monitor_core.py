from utils.check_host_utils import check_host
from concurrent.futures import ThreadPoolExecutor, as_completed
from view.display import MonitDisplay
from utils.clear_utils import Clean
import threading
from view.banner import Banner

lock = threading.Lock()

class Monit:

    def __init__(self, HOST):
        

        self.host = HOST
        #self.port = PORT
        #self.common_port = PORT.get('common_port')
        
        self.list_active_host = []
        self.list_inactive_host = []
        self.list_total_host = []


        self.list_previous_active_host = []
        self.list_previous_inactive_host = []

        self.dic_active_host = {}
        self.dic_active_port_host = {}
        self.dic_active_addr_host = {}


   
    def all_run_threads(self,func):


        results = []
        with ThreadPoolExecutor(max_workers=10) as executor:
        
            futures = {
                        executor.submit(func, host, details['addr'], port):(host,port)
                        for host, details in self.host.items()
                        for port in details['ports']
                        
                        }
            
            for future in as_completed(futures):
                host, port = futures[future]
                
                result = future.result()
                status = result[2]

                results.append(future.result())
                

        return results


    def separete_results(self):
        
        results = self.all_run_threads(check_host)


        for nome,addr,port, status in results:
            

            self.list_total_host.append(f'{nome}:{port}')
            if status:
                self.list_active_host.append(f'{nome}')
                #self.dic_active_host.update('{nome}':'{addr}', {nome}:{port})
                self.dic_active_port_host.update({f'{nome}':f'{port}'})
                self.dic_active_addr_host.update({f'{nome}':f'{addr}'})
            else:
                self.list_inactive_host.append(f'{nome}:{port}')
    

    def get_active(self):

            with lock:
                
                Clean.clear_list(self.list_active_host,self.list_inactive_host,self.list_total_host)
                
                self.separete_results()

                self.list_total_host.sort()
                self.list_active_host.sort()
                self.list_inactive_host.sort()
                
                if self.list_previous_active_host != self.list_active_host:

                    Clean.clear_terminal()
                    Banner.sharingan()

                    display_host = MonitDisplay(active=self.list_active_host, total=self.list_total_host)
                    display_host.display_active()
                    #display_host.display_total()
                    self.list_previous_active_host = self.list_active_host.copy()
                    
                     
                
            return self.list_previous_active_host
            


       
    def get_inactive(self):

            with lock:
                
                Clean.clear_list(self.list_active_host,self.list_inactive_host,self.list_total_host)
                
                self.separete_results()

                self.list_total_host.sort()
                self.list_active_host.sort()
                self.list_inactive_host.sort()                
                
                if self.list_previous_inactive_host != self.list_inactive_host:

                    Clean.clear_terminal()
                    Banner.sharingan()
                    display_host = MonitDisplay(inactive=self.list_inactive_host, total=self.list_total_host)
                    display_host.display_inactive()
                    #display_host.display_total()
                    self.list_previous_inactive_host = self.list_inactive_host.copy()  

            return self.list_previous_inactive_host