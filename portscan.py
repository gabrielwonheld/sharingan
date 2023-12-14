import socket, sys, time

HOST = ['10.37.0.8', '10.37.0.4', '10.37.0.3', '10.37.0.15','10.37.0.11','intranet.11ct.eb.mil.br','intranet.5rcc.eb.mil.br','sped3.5rcc.eb.mil.br']
PORT = 80 #int(sys.argv[1])


while True:
    for i in HOST:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        timeout = s.settimeout(2)

        try:
            if s.connect_ex((i, PORT)) !=0 :
                #print(f'host: {i} porta berta: {PORT}')
                print(f'Inativo host: {i} porta fechada {PORT}')

            #elif ConnectionRefusedError:
            #    print(f'RECUSADO !!!! host: {i} porta fechada {PORT}')

        except socket.error as e:
            print(e)

        finally:
            s.close()