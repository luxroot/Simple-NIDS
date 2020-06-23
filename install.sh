#!/bin/sh

command -v python3 >/dev/null 2>&1 && apt install python3
command -v python3 -c "import netaddr" >/dev/null 2>&1 && python3 -m pip install netaddr
command -v python3 -c "from scapy.all import *" >/dev/null 2>&1 && python3 -m pip install scapy
