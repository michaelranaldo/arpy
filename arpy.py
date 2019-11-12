#!/usr/bin/python3
import time, ipaddress, os,sys
from scapy.all import *
from lib import logger

'''
might be worth adding switches for interfaces/verbosity/no colour etc?
'''

verbose = False
found_hosts={}

def stats_banner():
    delimeter = ' ' * 10
    msg = '|%sStatistics%s|' % (delimeter,delimeter)
    corner = logger.red_fg('+')
    bar = '-' * (len(msg) - 2)
    print(corner+bar+ corner)
    print(logger.red_fg(msg))
    print(corner+bar+ corner)

def arp_monitor_callback(packet):
    if ARP in packet and packet[ARP].op in (1,2):
        if not (packet.sprintf("%ARP.hwsrc%") in found_hosts):
            found_hosts[packet.sprintf("%ARP.hwsrc%")] = packet.sprintf("%ARP.psrc%")
            return logger.green.fg(packet.sprintf("%ARP.hwsrc% - %ARP.psrc%"))
        else:
            if verbose:
                logger.yellow.fg("Ignoring previously discovered host")

def determine_subnet_cidr(hosts):
    subnet_range = hosts[len(hosts) - 1] - hosts[0]
    stats_banner()
    logger.green.bullet("Subnet range is %s " % logger.green_fg(subnet_range))
    logger.green.bullet("The captured ip addresses range from %s to %s" % (logger.green_fg(ipaddress.IPv4Address(hosts[0])), logger.green_fg(ipaddress.IPv4Address(hosts[len(hosts) - 1]))))
    logger.green.bullet("Based on a sample of %s captured ip addresses" % logger.green_fg(len(hosts)))
    # powers of 2 til we get to something

    #spoopy stuff
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

    logger.yellow.bullet("Estimated subnet size: /%s" % logger.yellow_fg(cidr))
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

if os.geteuid() != 0:
    logger.red.fg('sudo up motherfucker')
    quit()

print('Listening for %s traffic' % logger.green_fg('ARP'))
print()

sniffo = AsyncSniffer(prn=arp_monitor_callback, filter="arp", store=0)

try :
    sniffo.start()
    time.sleep(30)
    sniffo.stop()
except KeyboardInterrupt:
    print()
    logger.red.fg("Well fuck you too buddy")
    sniffo.stop()
    quit()

if len(found_hosts) == 0:
    logger.red.fg("We ain't found shit")
    exit()

numeric_hosts=[]

for host in found_hosts:
    numeric_hosts.append(int(ipaddress.IPv4Address(found_hosts[host])))

numeric_hosts.sort()

cidr = determine_subnet_cidr(numeric_hosts)

network_address = str(ipaddress.IPv4Address(numeric_hosts[0]))+"/"+str(cidr)

network = ipaddress.ip_network(network_address, strict=False)

logger.green.bullet("The network is within a %s address range" % (logger.green_fg("public") if network.is_private else logger.green_fg("private")))

logger.green.bullet("Network address: %s" % logger.green_fg(network.network_address))

logger.green.bullet("Broadcast address: %s" % logger.green_fg((network.broadcast_address)))

logger.green.bullet("The network range is %s address(es)" % logger.green_fg(str(2 ** (32 - cidr))))

empty_addresses = ( 2 ** (32 - cidr) ) - len(found_hosts)

logger.yellow.bullet("There appear to be %s empty address(es)" % logger.yellow_fg(empty_addresses))
