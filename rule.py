from scapy.layers.inet import IP, TCP

from ipnetwork import IPNetwork
from scapy.all import *
from option import *
from port import Port
from protocol import Protocol


class Rule:
    def __init__(self, text):
        words = text.split(' ', 7)
        options = words[-1].strip()[1:-1].split(';')
        self.protocol = Protocol(words[1])
        self.srcIP = IPNetwork(words[2])
        self.srcPort = Port(words[3])
        self.dstIP = IPNetwork(words[5])
        self.dstPort = Port(words[6])
        self.options = []

        for option in options:
            if option.strip() == '':
                break
            option_type = option.split(':', 1)[0].strip()
            data = option.split(':', 1)[1].strip()
            if option_type == 'msg':
                self.message = data[1:-1]
            elif option_type == 'tos':
                self.options.append(Tos(data))
            elif option_type == 'len':
                self.options.append(Len(data))
            elif option_type == 'offset':
                self.options.append(Offset(data))
            elif option_type == 'seq':
                self.options.append(Seq(data))
            elif option_type == 'ack':
                self.options.append(Ack(data))
            elif option_type == 'flags':
                self.options.append(Flags(data))
            elif option_type == 'http_request':
                self.options.append(HttpRequest(data[1:-1]))
            elif option_type == 'content':
                self.options.append(Content(data[1:-1]))
            else:
                raise KeyError("Haven't matched")

    def __repr__(self):
        repr_string = f"Protocol {self.protocol}\n"
        repr_string += f"Source {self.srcIP} {self.srcPort}\n"
        repr_string += f"Destination {self.dstIP} {self.dstPort}\n"
        repr_string += f"Message : {self.message}\n"
        repr_string += f"{len(self.options)} options --\n"
        for r in self.options:
            repr_string += r.__repr__() + '\n'
        return repr_string


    def match(self, _packet):
        print("match called")
        if not self.protocol.match(_packet):
            return False
        if not self.srcIP.match(_packet[IP].src):
            return False
        if not self.srcPort.match(_packet[IP].payload.sport):
            return False
        if not self.dstIP.match(_packet[IP].dst):
            return False
        if not self.dstPort.match(_packet[IP].payload.dport):
            return False
        match_list = map(lambda x: x.match, self.options)
        match_result = []
        print("~~~~~~~~~~~~~~~~~")
        print(list(match_list))
        print("----------------")
        for f in match_list:
            match_result.append(f(_packet))
        return all(match_result)
