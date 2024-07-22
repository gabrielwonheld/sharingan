import os


class Clean():
    

    @staticmethod
    def clear_terminal():

        if os.name == 'posix':
            os.system('clear')

        elif os.name == 'nt':
            os.system('cls')

    @staticmethod
    def clear_list(*args):
        for lista in args:
            if isinstance(lista, list):
                lista.clear()
