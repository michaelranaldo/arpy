#!/usr/bin/python3
import time, ipaddress, argparse, os, sys
from scapy.all import *
from lib import logger
from scapy.error import Scapy_Exception

found_hosts={}
ignore = ['0.0.0.0']
arp=True
cdp=False

parser = argparse.ArgumentParser(description = "ARP listener")
parser.add_argument('-v', '--verbose', help='Verbose mode', action='count')
parser.add_argument('-t', '--time', type=int, help='Time to listen for ARP packets')
parser.add_argument('-I', '--interface', help='Set the listening interface. Defers to scapy if not set.', required=False)
parser.add_argument('-a', '--arp', help='Set the arp listener', default=True, action='store_true')
parser.add_argument('-c', '--cdp', help='Set the cdp listener', default=False, action='store_true')
args = parser.parse_args()

if args.verbose != None and int(args.verbose) > 0:
    verbose = True
else:
    verbose = False
listen_time = 30
if args.time != None:
    listen_time = int(args.time)
    if verbose:
        print("Set listen time to %s" % listen_time)

interface = args.interface
print("Listening on %s" % interface)

capture_filter = ""
def add_protocol_to_filter(capture_filter, protocol):
    if capture_filter == "":
        capture_filter = capture_filter + protocol 
    else:
        capture_filter = capture_filter + " or " + protocol
    return capture_filter

if args.arp:
    capture_filter = add_protocol_to_filter(capture_filter, "arp")
    arp=True
if args.cdp:
    capture_filter = add_protocol_to_filter(capture_filter, "ether dst 01:00:0c:cc:cc:cc")
    cdp=True

print("Capture filter is currently set to %s" % capture_filter)

def stats_banner():
    delimeter = ' ' * 10
    msg = '|%sStatistics%s|' % (delimeter,delimeter)
    corner = logger.red_fg('+')
    bar = '-' * (len(msg) - 2)
    print(corner+bar+ corner)
    print(logger.red_fg(msg))
    print(corner+bar+ corner)

def arp_mon(packet):
    if ARP in packet and packet[ARP].op in (1,2):
        if not (packet.sprintf("%ARP.hwsrc%") in found_hosts) and not (packet.sprintf("%ARP.psrc%") in ignore) and not (packet.sprintf("%ARP.pdst%") in ignore):
            found_hosts[packet.sprintf("%ARP.hwsrc%")] = packet.sprintf("%ARP.psrc%")
            return logger.green.fg(packet.sprintf("%ARP.hwsrc% - %ARP.psrc%"))
        else:
            if verbose:
                logger.yellow.fg("Ignoring previously discovered host")

def cdp_mon(packet):
    logger.yellow.bullet(".|..")


def monitor_callback(packet):
    if arp and ARP in packet:
        arp_mon(packet)
    if cdp and CDP in packet:
        cdp_mon(packet)


def determine_subnet_cidr(hosts):
    subnet_range = hosts[len(hosts) - 1] - hosts[0]
    final_host = ipaddress.IPv4Address(hosts[len(hosts) - 1])
    
    stats_banner()
    
    logger.green.bullet("Subnet range is %s " % logger.green_fg(subnet_range))
    logger.yellow.bullet("Determining subnets...")
    logger.green.bullet("The captured ip addresses range from %s to %s" % (logger.green_fg(ipaddress.IPv4Address(hosts[0])), logger.green_fg(final_host)))
    logger.green.bullet("Based on a sample of %s captured ip addresses" % logger.green_fg(len(hosts)))

    # powers of 2 til we get to something

    # spoopy stuff
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

    logger.yellow.bullet("Estimated subnet size: /%s" % logger.yellow_fg(cidr))

    return cidr

def get_potential_addresses(found_hosts, network):
    if verbose:
        logger.yellow.bullet("Getting potential addresses...")
    empty_slots = []
    # Roll through the network and identify the first x empty slots
    for address in ipaddress.IPv4Network(network):
        if len(empty_slots) < 10:
            if int(ipaddress.IPv4Address(address)) not in found_hosts:
                if str(network.network_address) != str(ipaddress.IPv4Address(address)):
                    empty_slots.append(address)
        else:
            break
    logger.green.bullet("Try:")
    for address in empty_slots:
        logger.green.bullet("  %s" % address)

if os.geteuid() != 0:
    logger.red.fg('sudo up motherfucker')
    quit()
    
if arp:
    print('Listening for %s traffic' % logger.green_fg('ARP'))
if cdp:
    print('Listening for %s traffic' % logger.green_fg('CDP'))
print()

if interface == None:
    sniffo = AsyncSniffer(prn=monitor_callback, filter=capture_filter, store=0)
else:
    sniffo = AsyncSniffer(prn=monitor_callback, filter=capture_filter, store=0, iface=interface)

try:
    sniffo.start()
    time.sleep(listen_time)
    if verbose:
        print("Stopping listener...")
    sniffo.stop()
except KeyboardInterrupt:
    print()
    if verbose:
        logger.red.fg("Well fuck you too buddy")
    sniffo.stop()
except Scapy_Exception:
    logger.red.fg("Failed to attach filter")
    logger.red.fg("Try attaching a filter with the -I flag")
    sniffo.stop()

if len(found_hosts) == 0:
    logger.red.fg("We ain't found shit")
    exit()

numeric_hosts=[]

for host in found_hosts:
    numeric_hosts.append(int(ipaddress.IPv4Address(found_hosts[host])))

numeric_hosts.sort()

cidr = determine_subnet_cidr(numeric_hosts)

# ipaddress compatible subnet string
full_network_address = str(ipaddress.IPv4Address(numeric_hosts[0]))+"/"+str(cidr)

network = ipaddress.ip_network(full_network_address, strict=False)

logger.green.bullet("The network is within a %s address range" % (logger.green_fg("public") if network.is_private else logger.green_fg("private")))

logger.green.bullet("Suspected subnet: %s" % network)

logger.green.bullet("Network address: %s" % logger.green_fg(network.network_address))

logger.green.bullet("Broadcast address: %s" % logger.green_fg((network.broadcast_address)))

logger.green.bullet("The network range is %s address(es)" % logger.green_fg(str(2 ** (32 - cidr))))

empty_addresses = ( 2 ** (32 - cidr) ) - len(found_hosts)

if empty_addresses > 0:
    logger.yellow.bullet("There appear to be %s empty address(es)" % logger.yellow_fg(empty_addresses))
    get_potential_addresses(found_hosts, network)
else:
    print("Sorry old boy, no spare addresses available")
