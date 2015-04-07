__author__ = 'Soteria'

# Sniff link-status and route request messages
# Extract relevant sequence numbers:
    ## IEEE sequence number
    ## zigbee NWK sequence number
    ## security header - Frame Counter
# Create new packet:
# Change sequence numbers in the new packet
# Create new packet data
# Encrypt the data with the key
# Inject!

import logging
logging.getLogger('scapy')

try:
	from scapy.all import *
except ImportError:
	print 'This Requires Scapy To Be Installed.'
	from sys import exit
	exit(-1)

a = Ether()/IP(dst="www.slashdot.org")/TCP()/"GET /index.html HTTP/1.0 \n\n"
IP().show()

def

if __name__ == '__main__':
	interact(mydict = globals(), mybanner = 'Hacking Demo')