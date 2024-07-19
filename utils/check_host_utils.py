import socket

def check_host(nome, ip, port):

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)

        try:
            result = s.connect_ex((ip, port))
            return nome, result == 0

        except:
            #print(f'Erro ao conectar a {ip}:{port}: {e}')
            return nome, False

        finally:
            s.close()