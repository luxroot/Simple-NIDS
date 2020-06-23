from scapy.all import *
from scapy.layers.inet import TCP, UDP

httpMethodList = [b'HTTP', b'GET', b'HEAD', b'POST', b'PUT', b'DELETE', b'CONNECT', b'OPTIONS', b'TRACE', b'PATCH']


class Protocol:
    def __init__(self, text):
        if text not in ['tcp', 'udp', 'http', 'any']:
            raise ValueError
        if text == 'any':
            self.any = True
        else:
            self.any = False
        self.protocol = text

    def __repr__(self):
        if self.any:
            return "Protocol of any"
        else:
            return "Protocol of "+self.protocol

    def match(self, packet):
        if self.any:
            return True
        if self.protocol == "udp" and UDP in packet:
            return True
        if self.protocol == "tcp" and TCP in packet:
            return True
        if self.protocol == "http" and TCP in packet:
            if len(packet[TCP].payload) == 0:
                return False
            print(packet[TCP].load)
            content = packet[TCP].load
            if content and any(map(lambda x: content.startswith(x), httpMethodList)):
                return True
        return False
