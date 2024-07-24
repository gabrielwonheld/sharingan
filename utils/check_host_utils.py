import socket

def check_host(nome, addr, port):

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)

        try:
            result = s.connect_ex((addr, port))
            return nome,addr, port, result == 0

        except:
            #print(f'Erro ao conectar a {ip}:{port}: {e}')
            return nome,addr, port, False

        finally:
            s.close()
