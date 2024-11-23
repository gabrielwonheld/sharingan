import math

class Progress_bar():

    @staticmethod
    def progress_callback(current, total):
        percent_complete = (current / total) * 100
        num_hash = math.floor(percent_complete)
        barra = '#' * num_hash
        #print(f"Progresso: {percent_complete:.2f}% ({current} de {total} bytes)", end="\r")
        print(f"\rProgresso: {percent_complete:.2f}% [{barra:<100}] ({current} de {total} bytes)", end='')
