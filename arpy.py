#!/usr/bin/python3

from scapy.all import *
import time, ipaddress

verbose = False
found_hosts={}

def arp_monitor_callback(packet):
    if ARP in packet and packet[ARP].op in (1,2):
        if not (packet.sprintf("%ARP.hwsrc%") in found_hosts):
            found_hosts[packet.sprintf("%ARP.hwsrc%")] = packet.sprintf("%ARP.psrc%")
            return packet.sprintf("Found New %ARP.hwsrc% %ARP.psrc%")
        else:
            if verbose:
                print("Ignoring previously discovered host")

def determine_subnet_cidr(hosts):
    subnet_range = hosts[len(hosts) - 1] - hosts[0]
    print("Subnet range is %s " % subnet_range)
    print("Determining subnets...")
    print("The captured ip addresses range from %s to %s" % (ipaddress.IPv4Address(hosts[0]), ipaddress.IPv4Address(hosts[len(hosts) - 1])))
    print("Based on a sample of %s captured ip addresses" % len(hosts))
    # powers of 2 til we get to something
    exponent = 0
    estimated_subnet_size = 1
    cidr = 32
    chk = True
    while chk:
        if (2 ** exponent) < subnet_range:
            estimated_subnet_size = 2 ** exponent
            exponent = exponent + 1
            cidr = cidr - 1
        else:
            chk = False

    print("Estimated subnet size: /%s" % cidr)
    return cidr

# determine which IP addresses have been discovered so far

# determine strings of consecutive IP addresses, with a set maximum gap
# can i use some clever statistics shit here to find a likely empty spot
# within a valid range?

# suggest a top 10 most likely empty addresses, indicate a total number of
# empty addresses within a likely range

# have a prompt to "prod" addresses (loud mode) or just stay in 
# caterpillar drive mode

# So this previously was blocking as I wanted the constant updates
# even though i'd seen the non-blocking
# but the blocking fucks when you CTRL-C or otherwise quit
# Turns out the docs hadn't updated either, cause you can totally
# still call prn, so that's what we now do
sniffo = AsyncSniffer(prn=arp_monitor_callback, filter="arp", store=0)
try :
    sniffo.start()
    time.sleep(30)
    sniffo.stop()
except KeyboardInterrupt:
    print()
    print("Well fuck you too buddy")
    sniffo.stop()
print()
if len(found_hosts) == 0:
    print("We ain't found shit")
    exit()

numeric_hosts=[]
for host in found_hosts:
    numeric_hosts.append(int(ipaddress.IPv4Address(found_hosts[host])))
numeric_hosts.sort()
cidr = determine_subnet_cidr(numeric_hosts)
network_address = str(ipaddress.IPv4Address(numeric_hosts[0]))+"/"+str(cidr)
print(network_address)
network = ipaddress.ip_network(network_address, strict=False)
print("The network is within a %s address range" % ("public" if network.is_private else "private"))
print("Network address: %s" % network.network_address)
print("Broadcast address: %s" % network.broadcast_address)
print("The network range is %s address(es)" % str(2 ** (32 - cidr)))
empty_addresses = ( 2 ** (32 - cidr) ) - len(found_hosts)
print("There appear to be %s empty addresses" % empty_addresses)
