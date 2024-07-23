from utils.check_host_utils import check_host
from concurrent.futures import ThreadPoolExecutor, as_completed
from view.display import MonitDisplay
from utils.clear_utils import Clean
import threading
from view.banner import Banner

lock = threading.Lock()

class Monit:

    def __init__(self, HOST, PORT):
        

        self.host = HOST
        self.port = PORT
        
        self.list_active_host = []
        self.list_inactive_host = []
        self.list_total_host = []


        self.list_previous_active_host = []
        self.list_previous_inactive_host = []


   
    def all_run_threads(self,func):


        results = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            
            futures = {executor.submit(func, nome, self.host[nome], self.port[nome]):
                       nome for nome in self.host
                       }
            
            for future in as_completed(futures):
                results.append(future.result())
        
        return results


    def separete_results(self):
        
        results = self.all_run_threads(check_host)


        for nome, status in results:
            self.list_total_host.append(nome)
            if status:
                self.list_active_host.append(nome)
            else:
                self.list_inactive_host.append(nome)
                
       
        


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
                    display_host.display_total()
                    self.list_previous_active_host = self.list_active_host.copy()
                    
                     
                
            return self.list_previous_active_host



       
    def get_inactive(self):

            with lock:
                
                self.separete_results()
                if self.list_previous_inactive_host != self.list_inactive_host:

                    Clean.clear_terminal()
                    Banner.sharingan()
                    display_host = MonitDisplay(inactive=self.list_inactive_host, total=self.list_total_host)
                    #display_host.display_inactive()
                    display_host.display_total()
                    self.list_previous_inactive_host = self.list_inactive_host.copy()  

            return self.list_previous_inactive_host



















    def get_total(self):
       total = self.run_threads(check_host)
       self.process_results(total)
       display_host = MonitDisplay(total=self.list_total_host)
       return display_host.dysplay_total()
        
 
    def run_threads_active(self,func):
        
        
        #Processa e armazena dentro de results somente o resultado verdadeiro, ignorando o resultado falso.
        
        
        results = []
        with ThreadPoolExecutor(max_workers=10) as executor: 
            futures = {                     #ip de cada host  #porta de cada host
                executor.submit(func, nome, self.hosts[nome], self.port[nome]):
                nome for nome in self.hosts #Nesse laço de repetição, é determinado o nome de cada host, a partir da lista de host.
                }
            for future in as_completed(futures):
                nome, status = future.result() # future.result() retorna dois valores, o nome do host e o resultado booleano
                if status:
                    results.append(nome)
        
        return results
    
    def run_threads_inactive(self,argum):

        #Processa e armazena dentro de results somente o resultado Falso, ignorando o resultado verdadeiro.


        results = []
        with ThreadPoolExecutor(max_workers=10) as executor: #máximo de 10 Threads para não gerar sobrecarga na rede. Pode ser modificado futuramente.
            
            futures = {
                executor.submit(argum, nome, self.hosts[nome], self.port[nome]):
                nome for nome in self.hosts
                }
                        
            for future in as_completed(futures):
                nome, status = future.result() # future.result() retorna dois valores, o nome do host e o resultado booleano
                if status is False:
                    results.append(nome)
        return results  

    
    def process_results_active(self,results):
        #armazena somente o resultado verdadeiro na lista, ignorando o resultado negativo
        for nome in results:
            self.list_active_host.append(nome)

        
            
    def process_results_inactive(self,results):
        
        for nome in results:
            self.list_inactive_host.append(nome)

        

