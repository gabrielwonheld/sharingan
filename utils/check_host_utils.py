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


            '''import socket

def check_host(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)

    try:
        result = s.connect_ex((host, port))
        return host, port, result == 0  # Retorna o host, a porta e o status da conexão

    except Exception as e:
        #print(f'Erro ao conectar a {host}:{port}: {e}')
        return host, port, False  # Retorna o host, a porta e False em caso de exceção

    finally:
        s.close()'''