from rich.console import Console
from rich.table import Table
#from untils.monit import Monit
from utils.clear_utils import Clean


class MonitDisplay():


       def __init__(self,inactive=None, active=None, total=None):
              ...
              self.inactive_host = inactive if inactive is not None else [] 
              self.active_host = active if active is not None else []
              self.total_hosts = total if total is not None else [] 
              
       
       def dysplay_active(self):
       
              console = Console()
              table = Table(title="Sharingan",
                      show_header=True, header_style="bold red")
              
              table.add_column("Categoria", style="dim", width=20)
              table.add_column("Valor", justify="center", width=40)
              
              table.add_row("Hosts ativos", ', '.join(map(str,self.active_host)))
              table.add_row("Total de hosts", str(len(self.total_hosts)))
              table.add_row("Total de ativos", str(len(self.active_host)))

              
              console.print(table)

              print(self.inactive_host,self.active_host,self.total_hosts)
              Clean.clear_list(self.inactive_host,self.active_host,self.total_hosts)

              
              
       
       
       def dysplay_inactive(self):
       
              console = Console()
              table = Table(title="Sharingan",
                      show_header=True, header_style="bold red")
              
              table.add_column("Categoria", style="dim", width=20)
              table.add_column("Valor", justify="center", width=40)
              
              table.add_row("Hosts Inativos", ', '.join(map(str,self.inactive_host)))
              table.add_row("Total de hosts", str(len(self.total_hosts)))
              table.add_row("Total de Inativos", str(len(self.inactive_host)))

              console.print(table)
              #Clean.clear_list(self.inactive_host,self.active_host,self.total_hosts)

       def dysplay_total(self):
              ...
        



