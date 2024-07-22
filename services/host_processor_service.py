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