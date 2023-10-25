import os

def clear():
    
    if os.name == 'posix':
        os.system('clear')

    elif os.name == 'nt':
        os.system('cls')

