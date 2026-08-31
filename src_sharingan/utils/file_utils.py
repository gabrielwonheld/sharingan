import sys


class Yaml:
    @staticmethod
    def verif_yaml(file):

        if file.endswith(('.yaml', '.yml')):
            return file
        else:
            print('File is not in .yaml format')


class FileOutPut:
    def output_file(file, *lista):

        try:
            with open(file, 'w') as f:
                # Converts each list item to a string and writes it to the file
                for item in lista:
                    if isinstance(item, (list, tuple, set)):
                        f.write('\n'.join(map(str, item)) + '\n')
                    else:
                        f.write(str(item) + '\n')
            return True
        except Exception as e:
            print(f'Error saving to file {file}: {e}')
            return False
