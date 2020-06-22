from abc import abstractmethod

from scapy.all import *
from scapy.layers.inet import IP, TCP

from tcpFlag import of_string


class Option:
    @abstractmethod
    def match(self, _packet):
        pass


class Tos(Option):
    def __init__(self, text):
        self.tos = int(text)

    def match(self, _packet):
        return self.tos == _packet[IP].tos


class Len(Option):
    def __init__(self, text):
        self.len = int(text)

    def match(self, _packet):
        return self.len == _packet[IP].ihl


class Offset(Option):
    def __init__(self, text):
        self.offset = int(text)

    def match(self, _packet):
        return self.offset == _packet[IP].frag


class Seq(Option):
    def __init__(self, text):
        self.seq = int(text)

    def match(self, _packet):
        return self.seq == _packet[TCP].seq


class Ack(Option):
    def __init__(self, text):
        self.ack = int(text)

    def match(self, _packet):
        return self.ack == _packet[TCP].ack


class Flags(Option):
    def __init__(self, text):
        self.flags = of_string(text)

    def match(self, _packet):
        return self.flags == (self.flags & _packet[TCP].flags)


class HttpRequest(Option):
    def __init__(self, text):
        self.httpRequest = text

    def match(self, _packet):
        return _packet[TCP].payload.load.decode().startswith(self.httpRequest)


class Content(Option):
    def __init__(self, text):
        self.content = text

    def match(self, _packet):
        return self.content in _packet.payload.payload.load.decode()
