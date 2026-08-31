from utils.clear_utils import Clean


class MonitDisplay:
    def __init__(self, inactive=None, active=None, total=None):
        self.inactive_host = inactive if inactive is not None else {}
        self.active_host = active if active is not None else {}
        self.total_hosts = total if total is not None else {}
        self.compara_lista_porta = []

    # Function that creates a divider
    def create_divider(self, title=''):
        width = 60  # Default divider width
        divider = '-' * width
        if title:
            # Centers the title in the divider
            title = f' {title} '
            mid = width // 2
            return f'{divider[:mid - len(title)//2]}{title}{divider[mid + len(title)//2:]}'
        return divider

    def compara_porta(self, lista_portas):

        if lista_portas != self.compara_lista_porta:
            self.compara_lista_porta = lista_portas.copy()
            print(self.compara_lista_porta)
            return True

    def display_active(self, hosts):
        largura_divisor = 40
        total_hosts = 0
        total_hosts_ativos = 0

        port_list = [
            porta for porta in hosts.values() for porta in porta.ports_active
        ]

        if self.compara_porta(sorted(port_list)):

            Clean.clear_terminal()

            print(self.create_divider('Sharingan - Active Hosts'))

            for host in hosts.values():
                total_hosts += 1
                if len(host.ports_active) < 1:
                    continue
                host_formatado = f'{host.nome:<7}'
                divisor = '-' * (largura_divisor - len(host_formatado))

                for porta in host.ports_active:
                    total_hosts_ativos += 1
                    porta_formatada = f'[\033[32m{porta}\033[0m]'
                    print(f'{host_formatado}{divisor}{porta_formatada}')

            print(f'Total Hosts:{len(port_list)} ')
            print(f'Total Active Hosts:{total_hosts_ativos} ')

    # Function that displays inactive hosts
    def display_inactive(self,hosts):
        largura_divisor = 40
        total_hosts = 0
        total_hosts_inativos = 0

        port_list = [
            porta for porta in hosts.values() for porta in porta.ports_inactive
        ]

        if self.compara_porta(sorted(port_list)):

            Clean.clear_terminal()

            print(self.create_divider('Sharingan - Inactive Hosts'))

            for host in hosts.values():
                total_hosts += 1
                if len(host.ports_inactive) < 1:
                    continue
                host_formatado = f'{host.nome:<7}'
                divisor = '-' * (largura_divisor - len(host_formatado))

                for porta in host.ports_inactive:
                    total_hosts_inativos += 1
                    porta_formatada = f'[\033[31m{porta}\033[0m]'
                    print(f'{host_formatado}{divisor}{porta_formatada}')

            print(f'Total Hosts:{len(port_list)} ')
            print(f'Total Active Hosts:{total_hosts_inativos} ')



    def display_total(self):
        print(self.create_divider('Active Hosts with Ports'))

        for host, portas in self.active_host.items():
            host_formatado = f'{host:<20}'
            divisor = '-' * 40

            for porta in portas:
                porta_formatada = f'[\033[32m{porta}\033[0m]'
                print(f'{host_formatado}{divisor}{porta_formatada}')


class Parserdisplay:
    def __init__(self, emails, links):

        self.emails = emails
        self.links = links

    def display_parser(self):

        print('\nEmails found:')
        print('\n'.join(self.emails))

        print('\nLinks visited:')
        print('\n'.join(self.links))
