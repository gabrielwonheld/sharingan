import socket, sys

HOST = '192.168.56.1' #sys.argv[1]
PORT = 3306#int(sys.argv[2])

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

res = s.connect_ex((HOST, PORT))

print(res)
'''if res == 0:
    print ('porta aberta')
else:
    print('porta cerrada')
    '''