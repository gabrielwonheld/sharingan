import socket
import threading
#import os





class Hosts():

    def __init__(self, hosts, port):
        self.hosts = hosts
        self.port = port

    def check_host(self, host, port):

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)

        try:
            result = s.connect_ex((host, port))

            if result == 0:
                 ... #print(f'Ativo: {host}:{port}')
            else:
                print(f'Inativo: {host}:{port}')

        except socket.error as e:
            print(f'Erro ao conectar a {host}:{port}: {e}')

        finally:
            s.close()


    # Crie uma thread para cada host
    def threads(self):

        threads = []
        for host in self.hosts:
            thread = threading.Thread(target=self.check_host, args=(host, self.port))
            thread.daemon = True
            threads.append(thread)
            thread.start()

    # Aguarde todas as threads terminarem
        for thread in threads:
            thread.join()