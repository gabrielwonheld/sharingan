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
        largura_divisor = 40
        
        print(self.create_divider("Sharingan - Hosts Ativos"))
       
        for host, portas in self.active_host.items():
            host_formatado = f"{host:<7}"  
            divisor = '-' * (largura_divisor - len(host_formatado))

            for porta in portas:
                porta_formatada = f"[\033[32m{porta}\033[0m]"
                print(f"{host_formatado}{divisor}{porta_formatada}")

        print(f"Total de Hosts:{len(self.total_hosts)} ")    
        print(f"Total de Hosts Ativos:{len(self.active_host)} ")    


    # Função que exibe os hosts inativos
    def display_inactive(self):
        largura_divisor = 40

        print(self.create_divider("Sharingan - Hosts Inativos"))
        
        for host, portas in self.inactive_host.items():
            host_formatado = f"{host:<7}" 
            divisor = (largura_divisor - len(host_formatado)) * '-'
 
            for porta in portas:
                porta_formatada = f"[\033[31m{porta}\033[0m]"
                print(f"{host_formatado}{divisor}{porta_formatada}")
                
        print(f"\nTotal de Hosts:{len(self.total_hosts)}")
        print(f"Total de Hosts Inativos:{len(self.inactive_host)}")

    
    def display_total(self):
        print(self.create_divider("Hosts Ativos com Portas"))

        for host, portas in self.active_host.items():
            host_formatado = f"{host:<20}"  
            divisor = '-' * 40 

            for porta in portas:
                porta_formatada = f"[\033[32m{porta}\033[0m]" 
                print(f"{host_formatado}{divisor}{porta_formatada}")


