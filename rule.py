from scapy.layers.inet import IP, TCP

from ipnetwork import IPNetwork
from scapy.all import *
from option import *
from port import Port
from protocol import Protocol, is_http

long_flags = dict(F='FIN', S='SYN', R='RST', P='PSH', A='ACK', U='URG', E='ECE', C='CWR')


def red(x):
    return '\033[91m' + x + '\033[0m'


def check_option(options, pkt, cls):
    for ist in options:
        if isinstance(ist, cls) and ist.match(pkt):
            return True
    return False


class Rule:
    def __init__(self, text):
        self.text = text
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
                self.content = data
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

    def __str__(self):
        return self.text

    def match(self, _packet):
        if IP not in _packet:
            return False
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
        for f in match_list:
            match_result.append(f(_packet))
        return all(match_result)

    def get_formatted(self, pkt):
        val = f"Rule: {self.text}\n"
        val += "=====================\n"
        val += "[IP header]\n"
        val += f"Version: {pkt[IP].version}\n"
        if check_option(self.options, pkt, Len):
            val += red(f"Header Length: {pkt[IP].ihl * 4} bytes\n")
        else:
            val += f"Header Length: {pkt[IP].ihl * 4} bytes\n"
        if check_option(self.options, pkt, Tos):
            val += red(f"ToS: {hex(pkt[IP].tos)}\n")
        else:
            val += f"ToS: {hex(pkt[IP].tos)}\n"
        if check_option(self.options, pkt, Offset):
            val += red(f"Fragment Offset: {pkt[IP].frag}\n")
        else:
            val += f"Fragment Offset: {pkt[IP].frag}\n"
        if not self.srcIP.any and self.srcIP.match(pkt[IP].src):
            val += red(f"Source: {pkt[IP].src}\n")
        else:
            val += f"Source: {pkt[IP].src}\n"
        if not self.dstIP.any and self.dstIP.match(pkt[IP].dst):
            val += red(f"Destination: {pkt[IP].dst}\n")
        else:
            val += f"Destination: {pkt[IP].dst}\n"
        val += '\n'

        if TCP in pkt:
            val += "[TCP header]\n"
            if not self.srcPort.any and self.srcPort.match(pkt[TCP].sport):
                val += red(f"Source Port: {pkt[TCP].sport}\n")
            else:
                val += f"Source Port: {pkt[TCP].sport}\n"
            if not self.dstPort.any and self.dstPort.match(pkt[TCP].dport):
                val += red(f"Destination Port: {pkt[TCP].dport}\n")
            else:
                val += f"Destination Port: {pkt[TCP].dport}\n"
            if check_option(self.options, pkt, Seq):
                val += red(f"Sequence Number: {pkt[TCP].seq}\n")
            else:
                val += f"Sequence Number: {pkt[TCP].seq}\n"
            if check_option(self.options, pkt, Ack):
                val += red(f"Acknowledgement Number: {pkt[TCP].ack}\n")
            else:
                val += f"Acknowledgement Number: {pkt[TCP].ack}\n"
            packet_flags = ', '.join([long_flags[x] for x in pkt.sprintf('%TCP.flags%')])
            if check_option(self.options, pkt, Flags):
                val += red(f"Flags: {packet_flags}\n")
            else:
                val += f"Flags: {packet_flags}\n"

            if len(pkt[TCP].payload) != 0:
                val += "\n[TCP payload]\n"
            payload = pkt[TCP].load.decode()

            if is_http(pkt):
                http_method = payload.split(' ', 1)[0]

                if check_option(self.options, pkt, HttpRequest):
                    val += red(f"HTTP Request: {http_method}\n")
                else:
                    val += f"HTTP Request: {http_method}\n"

            if check_option(self.options, pkt, Content):
                val += f"Payload: {payload.replace(self.content, red(self.content))}\n"
            else:
                val += f"Payload: {payload}\n"

        val += "=====================\n"
        val += f"Message: {self.message}"
        return val
