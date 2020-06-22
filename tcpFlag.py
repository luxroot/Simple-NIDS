from enum import IntEnum
from functools import reduce


class Flag(IntEnum):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


flagTable = {'F': Flag.FIN, 'S': Flag.SYN, 'R': Flag.RST, 'P': Flag.PSH, 'A': Flag.ACK, 'U': Flag.URG, 'E': Flag.ECE,
             'C': Flag.CWR}


def of_string(text):
    return reduce(lambda a, b: a | b, [flagTable[x] for x in list(text)], 0)
