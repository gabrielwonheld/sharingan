from rich.console import Console
from rich.table import Table

class HostsDisplay():


       def __init__(self,inactive, active):
              ...
              self.inactive_host = inactive
              self.active_host = active
              #self.total_hosts = total

       
       def dysplay_active(self,total):
       
              console = Console()
              table = Table(title="Sharingan",
                      show_header=True, header_style="bold red")
              
              table.add_column("Categoria", style="dim", width=20)
              table.add_column("Valor", justify="center", width=40)
              
              table.add_row("Hosts ativos", ', '.join(map(str,self.active_host)))
              table.add_row("Total de hosts", str(len(total)))
              table.add_row("Total de hosts ativos", str(len(self.active_host)))

              console.print(table)
              self.active_host.clear()
       
       
       
       def dysplay_inactive(self,total):
       
              console = Console()
              table = Table(title="Sharingan",
                      show_header=True, header_style="bold red")
              
              table.add_column("Categoria", style="dim", width=20)
              table.add_column("Valor", justify="center", width=40)
              
              table.add_row("Hosts Inativos", ', '.join(map(str,self.inactive_host)))
              table.add_row("Total de hosts", str(len(total)))
              table.add_row("Total de hosts Inativos", str(len(self.inactive_host)))

              console.print(table)
              self.inactive_host.clear()
        



