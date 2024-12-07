class Host:
    def __init__(self, nome, addr) -> None:

        self.ports_active = []
        self.ports_inactive = []
        self.nome = nome
        self.addr = addr

    def add_port_active(self, port):

        self.ports_active.append(port)

    def add_port_inactive(self, port):

        self.ports_inactive.append(port)
