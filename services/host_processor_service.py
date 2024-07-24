import yaml, sys


class Host():


    @staticmethod
    def read_yaml_host():

        file = sys.argv[1]
        
        if file.endswith(('.yaml','.yml')):
            
            try:
                with open(file, 'r') as arquivo:

                    data = yaml.safe_load(arquivo)
                    #ports = data.get('ports', {})
                    hosts = data.get('hosts',{})
                    common_port = data.get('common_port', None)
                    

                    
                    if common_port:
 
                        ports = {host: common_port for host in hosts}
                    
                    else:
                        ports = {host: details['ports'] for host, details in hosts.items()}
                    
                    
                    return hosts, ports
                
            except Exception as e:
                print(e)