from utils.clear_utils import Clean


class MonitDisplay:
    def __init__(self, inactive=None, active=None, total=None):
        self.inactive_host = inactive if inactive is not None else {}
        self.active_host = active if active is not None else {}
        self.total_hosts = total if total is not None else {}
        self.compara_lista_porta = []

    # Função que cria um divisor
    def create_divider(self, title=''):
        width = 60  # Largura padrão do divisor
        divider = '-' * width
        if title:
            # Centraliza o título no divisor
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

            print(self.create_divider('Sharingan - Hosts Ativos'))

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

            print(f'Total de Hosts:{len(port_list)} ')
            print(f'Total de Hosts Ativos:{total_hosts_ativos} ')

    # Função que exibe os hosts inativos
    def display_inactive(self):
        largura_divisor = 40

        print(self.create_divider('Sharingan - Hosts Inativos'))

        for host, portas in self.inactive_host.items():
            host_formatado = f'{host:<7}'
            divisor = (largura_divisor - len(host_formatado)) * '-'

            for porta in portas:
                porta_formatada = f'[\033[31m{porta}\033[0m]'
                print(f'{host_formatado}{divisor}{porta_formatada}')

        print(f'\nTotal de Hosts:{len(self.total_hosts)}')
        print(f'Total de Hosts Inativos:{len(self.inactive_host)}')

    def display_total(self):
        print(self.create_divider('Hosts Ativos com Portas'))

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

        print('\nEmails encontrados:')
        print('\n'.join(self.emails))

        print('\nLinks visitados:')
        print('\n'.join(self.links))
