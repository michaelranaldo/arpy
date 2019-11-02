#!/usr/bin/python3

from scapy.all import *
import time

found_hosts={}

def arp_monitor_callback(packet):
    if ARP in packet and packet[ARP].op in (1,2):
        print(packet.sprintf("%ARP.hwsrc%"))
        found_hosts[packet.sprintf("%ARP.hwsrc%")] = packet.sprintf("%ARP.psrc%")
        return packet.sprintf("Found %ARP.hwsrc% %ARP.psrc%")

# determine which potential subnets IP address could be in
## this will likely tie in with the below
## i.e. if only 255 addresses have been found, perhaps this is on balance
## a /24, therefore suggest quiet sports within the /24

# determine which IP addresses have been discovered so far

# determine strings of consecutive IP addresses, with a set maximum gap
# can i use some clever statistics shit here to find a likely empty spot
# within a valid range?

# suggest a top 10 most likely empty addresses, indicate a total number of
# empty addresses within a likely range

# have a prompt to "prod" addresses (loud mode) or just stay in 
# caterpillar drive mode

sniff(prn=arp_monitor_callback, filter="arp", store=0)
print()
print(found_hosts)
