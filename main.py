import sys

from scapy.all import *

from ruleMaker import RuleMaker

rm = RuleMaker(sys.argv[1])
rules = rm.getRules()



def isMatched(packet, rules):
    packet.display()
    for i, v in enumerate(rules):
        if v.match(packet):
            print(i)
            print(v)
            break


sniff(prn=lambda x: isMatched(x, rules), filter="tcp or udp")
# sniff(prn=lambda x: x.display(), filter="tcp or udp")
