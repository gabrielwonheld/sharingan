import yaml
from utils import file_utils


class Host:
    @staticmethod
    def read_yaml_host(hosts_file):

        if file_utils.Yaml.verif_yaml(hosts_file):

            try:
                with open(hosts_file, 'r') as arquivo:

                    data = yaml.safe_load(arquivo)
                    hosts = data.get('hosts', {})
                    common_port = data.get('common_port', None)

                    for host, info in hosts.items():
                        if 'ports' not in info and common_port:
                            info['ports'] = [common_port]

                return hosts

            except Exception as e:
                print(e)
