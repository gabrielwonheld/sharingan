import yaml, sys


class Host():


    @staticmethod
    def read_yaml_host():

        file = sys.argv[1]
        
        if file.endswith(('.yaml','.yml')):
            
            try:
                with open(file, 'r') as arquivo:

                    data = yaml.safe_load(arquivo)
                    ports = data.get('ports', {})
                    common_port = data.get('common_port', {})
                    hosts = data.get('hosts',{})

                    
                    if common_port:
 
                        ports = {host: common_port for host in hosts}
                    
                    
                    return hosts, ports
                
            except Exception as e:
                print(e)




print(Host.read_yaml_host())


'''if hosts:    
    for a in hosts.values():    
        print(a)
        #print(b)
    if ports:
        for b in ports.values():
            print(b)
#print(ports)'''

'''if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python script.py <caminho_para_arquivo_yaml>")
    else:
        #file_path = sys.argv[1]
        hosts, ports = Host.read_yaml_host()

        if hosts:
            print("Hosts:")
            for ip in hosts.values():
                print(ip)

            if ports:
                print("\nPorts:")
                for port in ports.values():
                    print(port)
            else:
                print("\nNenhuma porta especificada.")'''