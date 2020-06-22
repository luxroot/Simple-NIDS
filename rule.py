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
                raise KeyError(f"{option_type} haven't matched")

    def match(self, packet):
        match_list = [self.protocol, self.srcIP, self.srcPort, self.dstIP, self.dstPort]
        match_list.extend(self.options)
        match_list = map(lambda x: x.match, match_list)
        match_result = map(match_list, [packet] * len(packet))
        return all(match_result)
