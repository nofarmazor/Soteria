__author__ = 'Soteria'

# 1. Sniff link-status and route request messages
# 2. Extract relevant sequence numbers:
    ## IEEE sequence number
    ## zigbee NWK sequence number
    ## security header - Frame Counter
# 3. Create new packet:
# 4. Change sequence numbers in the new packet
# 5. Create new packet data
# 6. Encrypt the data with the keyc1
# 7. Inject!

import logging
log_killerbee = logging.getLogger('scapy.killerbee')

try:
	from scapy.all import *
except ImportError:
	print 'This Requires Scapy To Be Installed.'
	from sys import exit
	exit(-1)

#from killerbee import *
from killerbee.scapy_extensions import *

del hexdump
from scapy.utils import hexdump				# Force using Scapy's hexdump()
import os

DEFAULT_KB_CHANNEL = 11
DEFAULT_KB_DEVICE = '10.10.10.2'

#Sniff packets
kbsniff(DEFAULT_KB_CHANNEL,2,DEFAULT_KB_DEVICE)