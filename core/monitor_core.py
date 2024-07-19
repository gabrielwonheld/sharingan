from utils.check_host_utils import check_host
from concurrent.futures import ThreadPoolExecutor, as_completed
from view.display import MonitDisplay



class Monit:

    def __init__(self, HOST, PORT):
        #self.hosts = config['hosts']
        #self.hosts = config['hosts']
        self.hosts = HOST
        self.port = PORT
        
        self.list_active_host = []
        self.list_inactive_host = []
        self.list_total_host = []


   
    def all_run_threads(self,argum):

        # Executa as Threads.
        #argum é a função run_threads irá executar.
        #essa faixa de código ainda amarra o run_threads() a check_host(), mas pode ser modificado futuramente.
        #Processa e armazena todos os resultados das threads, resultados verdadeiros e falsos.


        results = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            
            futures = {executor.submit(argum, nome, self.hosts[nome], self.port[nome]):
                       nome for nome in self.hosts
                       }
            
            for future in as_completed(futures):
                results.append(future.result())
        
        return results


    def all_process_results(self,results):
        
        
        #armazena o todos os resultados nas listas, tanto verdadeiros quanto falsos da função run_threads()

        for nome, status in results:
            self.list_total_host.append(nome)
            if status:
                self.list_active_host.append(nome)
            else:
                self.list_inactive_host.append(nome)





   
    def run_threads_active(self,argum):
        
        
        #Processa e armazena dentro de results somente o resultado verdadeiro, ignorando o resultado falso.
        
        
        results = []
        with ThreadPoolExecutor(max_workers=10) as executor: 
            futures = {
                executor.submit(argum, nome, self.hosts[nome], self.port[nome]):
                nome for nome in self.hosts
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

        




    #retorna somente o resultado requerido
    def get_active(self):
        
        
        active = self.run_threads_active(check_host)
        self.process_results_active(active)
        display_host = MonitDisplay(active=self.list_active_host,total=self.list_total_host)
        return display_host.dysplay_active()
    
    
    def get_inactive(self):
       inactive = self.run_threads_inactive(check_host)
       self.process_results_inactive(inactive)
       display_host = MonitDisplay(inactive=self.list_inactive_host,total=self.list_total_host)
       return display_host.dysplay_inactive()
       

    def get_total(self):
       total = self.run_threads(check_host)
       self.process_results(total)
       display_host = MonitDisplay(total=self.list_total_host)
       return display_host.dysplay_total()
        
