from scapy.all import *
from scapy.layers.inet import UDP, TCP

httpMethodList = ['HTTP', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']


class Protocol:
    def __init__(self, text):
        if text not in ['tcp', 'udp', 'http', 'any']:
            raise ValueError
        if text == 'any':
            self.any = True
        else:
            self.any = False
        self.protocol = text

    def match(self, packet):
        if self.any:
            return True
        if self.protocol == "udp" and UDP in packet:
            return True
        if self.protocol == "tcp" and TCP in packet:
            return True
        if self.protocol == "http" and TCP in packet:
            content = packet.tcp.payload.load.decode()
            if any(map(lambda x: content.startwith(x), httpMethodList)):
                return True
        return False
