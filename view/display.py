'''from rich.console import Console
from rich.table import Table
#from untils.monit import Monit
from utils.clear_utils import Clean


class MonitDisplay():


       def __init__(self,inactive=None, active=None, total=None):
              ...
              self.inactive_host = inactive if inactive is not None else [] 
              self.active_host = active if active is not None else {}
              self.total_hosts = total if total is not None else [] 
              
       
       def display_active(self):
       
              console = Console()
              table = Table(title="Sharingan",
                      show_header=True, header_style="bold red")
              
              table.add_column("Categoria", style="dim", width=20)
              table.add_column("Valor", justify="center", width=40)
              
              table.add_row("Hosts ativos", ', '.join(map(str,self.active_host)))
              table.add_row("Total de hosts", str(len(self.total_hosts)))
              table.add_row("Total de ativos", str(len(self.active_host)))

              print(self.active_host)
              console.print(table)

              
              
              
       
       
       def display_inactive(self):
       
              console = Console()
              table = Table(title="Sharingan",
                      show_header=True, header_style="bold red")
              
              table.add_column("Categoria", style="dim", width=20)
              table.add_column("Valor", justify="center", width=40)
              
              table.add_row("Hosts Inativos", ', '.join(map(str,self.inactive_host)))
              table.add_row("Total de hosts", str(len(self.total_hosts)))
              table.add_row("Total de Inativos", str(len(self.inactive_host)))

              console.print(table)
              
       def display_total(self):
              print(f"{'Hosts Ativos'}")
              
              for row in self.active_host:
                     for porta in self.active_host[row]:

                            # Coloca o nome do host na primeira coluna com alinhamento à esquerda
                            row_formatado = f"{row:<7}"  # Largura fixa de 20 para o nome do host
                            
                            divisor = '-' * (40 + len(row_formatado))  # Ajusta o número de asteriscos
                            # Porta à direita com alinhamento à direita
                            porta_formatado = f"[\033[32m{porta:>1}\033[0m]"  # Largura fixa de 10 para a porta

                            # Exibe a linha formatada como no Ansible
                            print(f"{row_formatado}{divisor}{porta_formatado}")
'''
       


from utils.clear_utils import Clean


class MonitDisplay:

    def __init__(self, inactive=None, active=None, total=None):
        self.inactive_host = inactive if inactive is not None else {} 
        self.active_host = active if active is not None else {}
        self.total_hosts = total if total is not None else {} 

    # Função que cria um divisor
    def create_divider(self, title=""):
        width = 60  # Largura padrão do divisor
        divider = '-' * width
        if title:
            # Centraliza o título no divisor
            title = f" {title} "
            mid = width // 2
            return f"{divider[:mid - len(title)//2]}{title}{divider[mid + len(title)//2:]}"
        return divider



    def display_active(self):
       print(self.create_divider("Sharingan - Hosts Ativos"))
       
       for host, portas in self.active_host.items():
            host_formatado = f"{host:<7}"  # Largura fixa de 20 para o nome do host
            divisor = '-' * 40  # Tamanho fixo do divisor para portas

            for porta in portas:
                porta_formatada = f"[\033[32m{porta}\033[0m]"  # Cor verde para a porta
                print(f"{host_formatado}{divisor}{porta_formatada}")    


    # Função que exibe os hosts inativos
    def display_inactive(self):
        print(self.create_divider("Sharingan - Hosts Inativos"))
        
        for host, portas in self.inactive_host.items():
            host_formatado = f"{host:<7}"  # Largura fixa de 20 para o nome do host
            divisor = '-' * 40  # Tamanho fixo do divisor para portas

            for porta in portas:
                porta_formatada = f"[\033[31m{porta}\033[0m]"  # Cor vermelho para a porta
                print(f"{host_formatado}{divisor}{porta_formatada}")

    # Função que exibe os hosts ativos com portas
    def display_total(self):
        print(self.create_divider("Hosts Ativos com Portas"))

        for host, portas in self.active_host.items():
            host_formatado = f"{host:<20}"  # Largura fixa de 20 para o nome do host
            divisor = '-' * 40  # Tamanho fixo do divisor para portas

            for porta in portas:
                porta_formatada = f"[\033[32m{porta}\033[0m]"  # Cor verde para a porta
                print(f"{host_formatado}{divisor}{porta_formatada}")


