# imports scapy Utility

from scapy.all import *
from scapy.utils import *

# variable to store hexdump

hexdump = '1355b6767988295e00000000000300347e581e360000000000000000'

# Initialize a 802.11 structure from raw bytes

packet = Dot11(bytearray.fromhex(hexdump))

#scapy function to view the info

packet.summary()
packet.show()
