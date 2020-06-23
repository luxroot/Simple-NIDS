import sys

from scapy.all import *

from ruleMaker import RuleMaker

rm = RuleMaker(sys.argv[1])
rules = rm.get_rules()


def is_matched(_packet, _rules):
    for v in _rules:
        if v.match(_packet):
            print(v.get_formatted(_packet))
            break


sniff(prn=lambda x: is_matched(x, rules), filter="tcp or udp")
# sniff(prn=lambda x: x.display(), filter="tcp or udp")
