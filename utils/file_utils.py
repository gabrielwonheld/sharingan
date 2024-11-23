
import sys


class Yaml:

    @staticmethod
    def verif_yaml(file):
        
        if file.endswith(('.yaml','.yml')):
            return file
        else: 
            print('Arquivo não tem formato .yaml')

class FileOutPut():

    
    def output_file(file,*lista):
        
        try:
            with open(file, 'w') as f:
                # Converte cada item de lista para string e escreve no arquivo
                for item in lista:
                    if isinstance(item, (list, tuple, set)):
                        f.write('\n'.join(map(str, item)) + '\n')
                    else:
                        f.write(str(item) + '\n')
            return True
        except Exception as e:
                print(f"Erro ao salvar no arquivo {file}: {e}")
                return False
        
    


