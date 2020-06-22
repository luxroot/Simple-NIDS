from scapy.all import *
from ruleMaker import RuleMaker
import sys

rm = RuleMaker(sys.argv[1])
rules = rm.getRules()

print(len(rules))
print(rules[0].message)
print(rules[0].protocol.protocol)