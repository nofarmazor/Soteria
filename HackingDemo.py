__author__ = 'Soteria'


import logging
logging.getLogger('scapy')

try:
	from scapy.all import *
except ImportError:
	print 'This Requires Scapy To Be Installed.'
	from sys import exit
	exit(-1)


#def

#if __name__ == '__main__':
	#interact(mydict = globals(), mybanner = 'Hacking Demo')