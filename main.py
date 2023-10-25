from clear import clear
from threads import Hosts
from time import sleep



if __name__ == '__main__':
    HOSTS = ['192.168.0.1', '192.168.0.101', '192.168.0.126']
    PORT = 80

    check_hosts = Hosts(HOSTS, PORT)
    
    while True:
        check_hosts.threads()
        sleep(5)
        clear()
        