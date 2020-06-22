from abc import abstractmethod

from scapy.all import *

from tcpFlag import of_string


class Option:
    @abstractmethod
    def match(self, packet):
        pass


class Tos(Option):
    def __init__(self, text):
        self.tos = int(text)

    def match(self, packet):
        return self.tos == packet[IP].tos


class Len(Option):
    def __init__(self, text):
        self.len = int(text)

    def match(self, packet):
        return self.len == packet[IP].ihl


class Offset(Option):
    def __init__(self, text):
        self.offset = int(text)

    def match(self, packet):
        return self.offset == packet[IP].frag


class Seq(Option):
    def __init__(self, text):
        self.seq = int(text)

    def match(self, packet):
        return self.seq == packet[TCP].seq


class Ack(Option):
    def __init__(self, text):
        self.ack = int(text)

    def match(self, packet):
        return self.ack == packet[TCP].ack


class Flags(Option):
    def __init__(self, text):
        self.flags = of_string(text)

    def match(self, packet):
        return self.flags == (self.flags & packet[TCP].flags)


class HttpRequest(Option):
    def __init__(self, text):
        self.httpRequest = text

    def match(self, packet):
        return packet[TCP].payload.load.decode().startswith(self.httpRequest)


class Content(Option):
    def __init__(self, text):
        self.content = text

    def match(self, packet):
        return self.content in packet.payload.payload.load.decode()
