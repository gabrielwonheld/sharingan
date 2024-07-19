import yaml


class Yaml:

    @staticmethod
    def verif_yaml(file):
        
        if file.endswith(('.yaml','.yml')):
            return file
        else: 
            print('Arquivo não tem formato .yaml')
        


