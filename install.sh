#!/bin/bash

type -P python3 >/dev/null 2>&1 || apt install python3
python3 -m pip >/dev/null 2>&1 || apt install python3-pip -y
python3 -c "import netaddr" >/dev/null 2>&1 || sudo -H python3 -m pip install -U netaddr
python3 -c "from scapy.all import *" >/dev/null 2>&1 || sudo -H python3 -m pip install -U scapy
echo "All clear :)"