import sys

from scapy.all import *

from ruleMaker import RuleMaker

rm = RuleMaker(sys.argv[1])
rules = rm.getRules()



def isMatched(packet, rules):
    for i, v in enumerate(rules):
        if v.match(packet):
            print(i)
            break


# sniff(prn=lambda x: isMatched(x, rules), iface='lo', filter="tcp or udp")
sniff(prn=lambda x: x.display(), iface='lo', filter="tcp or udp")
