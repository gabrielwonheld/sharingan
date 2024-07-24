import yaml, sys

class Host():


    @staticmethod
    def read_yaml_host():

        file = sys.argv[1]
        
        if file.endswith(('.yaml','.yml')):
            
            try:
                with open(file, 'r') as arquivo:

                    data = yaml.safe_load(arquivo)
                    hosts = data.get('hosts',{})
                    common_port = data.get('common_port', None)
                    

                    
                    for host, info in hosts.items():
                        if 'ports' not in info and common_port:
                             info['ports'] = [common_port]

                    
                return hosts
                
            except Exception as e:
                print(e)