from utils.check_host_utils import check_host
from concurrent.futures import ThreadPoolExecutor, as_completed
from view.display import MonitDisplay
from utils.clear_utils import Clean
import threading

lock = threading.Lock()

class Monit:

    def __init__(self, HOST, PORT):
        #self.hosts = config['hosts']
        #self.hosts = config['hosts']
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


    def all_process_results(self):
        
        results = self.all_run_threads(check_host)
        self.list_total_host.clear()
        self.list_active_host.clear()
        self.list_inactive_host.clear()

        for nome, status in results:
            self.list_total_host.append(nome)
            if status:
                self.list_active_host.append(nome)
            else:
                self.list_inactive_host.append(nome)

        self.list_total_host.sort()
        self.list_active_host.sort()
        self.list_inactive_host.sort()
        
            
    '''def difList(self,previous_list, current_list):
            if previous_list != current_list:
                
                return self.list_active_host.copy()
            return previous_list'''

    def get_active(self):

            with lock:
                
                self.all_process_results()
                if self.list_previous_active_host != self.list_active_host:
                    Clean.clear_terminal()
                    display_host = MonitDisplay(active=self.list_active_host, total=self.list_total_host)
                    display_host.dysplay_active()
                    self.list_previous_active_host = self.list_active_host.copy()
                     
                
            return self.list_previous_active_host







    def get_inactive(self):
       #inactive = self.all_run_threads(check_host)
       self.all_process_results()
       display_host = MonitDisplay(inactive=self.list_inactive_host,total=self.list_total_host)
       return display_host.dysplay_inactive()
       




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

        

