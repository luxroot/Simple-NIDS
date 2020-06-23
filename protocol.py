from scapy.all import *
from scapy.layers.inet import TCP, UDP

httpMethodList = [b'HTTP', b'GET', b'HEAD', b'POST', b'PUT', b'DELETE', b'CONNECT', b'OPTIONS', b'TRACE', b'PATCH']


def is_http(_packet):
    if TCP not in _packet:
        return False
    if len(_packet[TCP].payload) == 0:
        return False
    content = _packet[TCP].load
    if content and any(map(lambda x: content.startswith(x), httpMethodList)):
        return True
    return False


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

    def match(self, _packet):
        if self.any:
            return True
        if self.protocol == "udp" and UDP in _packet:
            return True
        if self.protocol == "tcp" and TCP in _packet:
            return True
        if self.protocol == "http" and TCP in _packet:
            if is_http(_packet):
                return True
        return False
