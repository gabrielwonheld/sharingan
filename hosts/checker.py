import socket
import threading
#import os





class Hosts():

    def __init__(self, hosts, port):
        self.hosts = hosts
        self.port = port
        self.active_host = []
        self.inactive_host = []


    def check_host(self, host, port):

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)

        try:
            result = s.connect_ex((host, port))

            if result == 0:
                self.active_host.append(host)
        
            else:
                self.inactive_host.append(host)                
        
        
        except socket.error as e:
            print(f'Erro ao conectar a {host}:{port}: {e}')

        finally:
            s.close()


    # Make a thread for each host
    def threads(self):

        threads = []
        for host in self.hosts:
            thread = threading.Thread(target=self.check_host, args=(host, self.port))
            thread.daemon = True
            threads.append(thread)
            thread.start()

    # wait until all threads completed
        for thread in threads:
            thread.join()

    
    def get_active(self):
       #print(self.active_host)
       return self.active_host
    
    
    def get_inactive(self):
       return self.inactive_host
        