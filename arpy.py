#!/usr/bin/python3

from scapy.all import *
import time, ipaddress, argparse

found_hosts={}
ignore = ['0.0.0.0']

parser = argparse.ArgumentParser(description = "ARP listener")
parser.add_argument('-v', '--verbose', help='Verbose mode', action='count')
args = parser.parse_args()

if args.verbose != None and int(args.verbose) > 0:
    verbose = True
else:
    verbose = False

def arp_monitor_callback(packet):
    if ARP in packet and packet[ARP].op in (1,2):
        if not (packet.sprintf("%ARP.hwsrc%") in found_hosts) and not (packet.sprintf("%ARP.psrc%") in ignore) and not (packet.sprintf("%ARP.pdst%") in ignore):
            found_hosts[packet.sprintf("%ARP.hwsrc%")] = packet.sprintf("%ARP.psrc%")
            return packet.sprintf("Found New %ARP.hwsrc% %ARP.psrc%")
        else:
            if verbose:
                print("Ignoring previously discovered host")

def determine_subnet_cidr(hosts):
    subnet_range = hosts[len(hosts) - 1] - hosts[0]
    final_host = ipaddress.IPv4Address(hosts[len(hosts) - 1])
    if verbose:
        print("Subnet range is %s " % subnet_range)
        print("Determining subnets...")
        print("The captured ip addresses range from %s to %s" % (ipaddress.IPv4Address(hosts[0]), final_host))
        print("Based on a sample of %s captured ip addresses" % len(hosts))
    # powers of 2 til we get to something
    exponent = 0
    estimated_subnet_size = 1
    cidr = 32
    chk = True
    while chk:
        # if 2^x is less than the range of ip address
        # and if the maximum proposed range is still 
        # lower than the highest ip address
        network = ipaddress.ip_network(str(ipaddress.IPv4Address(numeric_hosts[0]))+"/"+str(cidr), strict=False)
        if (2 ** exponent) < subnet_range or final_host not in network:
            estimated_subnet_size = 2 ** exponent
            exponent = exponent + 1
            cidr = cidr - 1
        else:
            chk = False

    if verbose:
        print("Estimated subnet size: /%s" % cidr)
    return cidr

def get_potential_addresses(found_hosts, network):
    if verbose:
        print("Getting potential addresses...")
    empty_slots = []
    # Roll through the network and identify the first x empty slots
    for address in ipaddress.IPv4Network(network):
        if len(empty_slots) < 10:
            if int(ipaddress.IPv4Address(address)) not in found_hosts:
                if str(network.network_address) != str(ipaddress.IPv4Address(address)):
                    empty_slots.append(address)
        else:
            break
    print("Try:")
    for address in empty_slots:
        print("  %s" % address)

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
    if verbose:
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
full_network_address = str(ipaddress.IPv4Address(numeric_hosts[0]))+"/"+str(cidr)
network = ipaddress.ip_network(full_network_address, strict=False)
if verbose:
    print("The network is within a %s address range" % ("private" if network.is_private else "public"))
print("Suspected subnet: %s" % network)
empty_addresses = ( 2 ** (32 - cidr) ) - len(found_hosts)

if empty_addresses > 0:
    print("There appear to be %s empty addresses out of a maximum %s" % (empty_addresses, str(2**(32-cidr))))
    get_potential_addresses(found_hosts, network)
else:
    print("Sorry old boy, no spare addresses available")
