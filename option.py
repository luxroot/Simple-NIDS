from abc import abstractmethod

from scapy.all import *
from scapy.layers.inet import IP, TCP

from tcpFlag import of_string


class Option:
    def __init__(self, text):
        self.text = text

    def __repr__(self):
        return self.__class__.__name__ + ' ' + self.text

    @abstractmethod
    def match(self, _packet):
        pass


class Tos(Option):
    def __init__(self, text):
        super().__init__(text)
        self.tos = int(text)

    def match(self, _packet):
        return self.tos == _packet[IP].tos


class Len(Option):
    def __init__(self, text):
        super().__init__(text)
        self.len = int(text)

    def match(self, _packet):
        return self.len == _packet[IP].ihl * 4


class Offset(Option):
    def __init__(self, text):
        super().__init__(text)
        self.offset = int(text)

    def match(self, _packet):
        return self.offset == _packet[IP].frag


class Seq(Option):
    def __init__(self, text):
        super().__init__(text)
        self.seq = int(text)

    def match(self, _packet):
        return self.seq == _packet[TCP].seq


class Ack(Option):
    def __init__(self, text):
        super().__init__(text)
        self.ack = int(text)

    def match(self, _packet):
        return self.ack == _packet[TCP].ack


class Flags(Option):
    def __init__(self, text):
        super().__init__(text)
        self.flags = of_string(text)

    def match(self, _packet):
        return self.flags == (self.flags & _packet[TCP].flags)


class HttpRequest(Option):
    def __init__(self, text):
        super().__init__(text)
        self.httpRequest = text

    def match(self, _packet):
        return _packet[IP].payload.payload.load.decode().startswith(self.httpRequest)


class Content(Option):
    def __init__(self, text):
        super().__init__(text)
        self.content = text

    def match(self, _packet):
        return self.content in raw(_packet[IP].payload.payload).decode()
