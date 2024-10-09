import sys
from view.banner import Banner


class Validation():

    def __init__(self):

        self.args = sys.argv
        pass

    def validationArgs():
        
        qtdArgs = int(len(sys.argv))

        if qtdArgs < 2 or qtdArgs >= 4:
            Banner.modoUso()
            sys.exit(1)