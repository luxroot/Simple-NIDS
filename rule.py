from ip import IP
from option import *
from port import Port
from protocol import Protocol


class Rule:
    def __init__(self, text):
        words = text.split(' ', 7)
        options = words[-1].strip()[1:-1].split(';')
        self.protocol = Protocol(words[1])
        self.srcIP = IP(words[2])
        self.srcPort = Port(words[3])
        self.dstIP = IP(words[5])
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

    def match(self, packet):
        if not self.protocol.match(packet):
            return False
        if not self.srcIP.match(packet[IP].src):
            return False
        if not self.srcPort.match(packet[TCP].sport):
            return False
        if not self.dstIP.match(packet[IP].dst):
            return False
        if not self.dstPort.match(packet[TCP].dport):
            return False
        match_list = map(lambda x: x.match, self.options)
        match_result = []
        for f in match_list:
            match_result.append(f(packet))
        return all(match_result)