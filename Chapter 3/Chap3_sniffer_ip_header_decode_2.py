import socket

import os
import struct
from ctypes import *

# host to listen on
# host = "192.168.1.131" # IP of our Windows7 - Python Virtual Box Machine (on My ASUS Laptop)
host = "192.168.100.8" # IP of our MacBook Pro Machine
# our IP header
class IP(Structure): # Class Structure comes from ctypes module. Our IP class is inheriting from Structure class now.
    _fields_ = [
        ("ihl",         c_ubyte, 4), #ubyte == char in C
        ("version",     c_ubyte, 4),
        ("tos",         c_ubyte),
        ("len",         c_ushort),
        ("id",          c_ushort),
        ("offset",      c_ushort),
        ("ttl",         c_ubyte),
        ("protocol_num",c_ubyte),
        ("sum",         c_ushort),
        ("src",         c_ulong),
        ("dst",         c_ulong)
    ]

    def __new__(self, socket_buffer=None): # __new__ method is used for handling object creation. socket_buffer variable here is filled with the contents of "raw_buffer[0:20]" below in the script
                                            # The __new__ method of the IP class simply takes in the raw buffer (in this case, the 20 bytes of data we receive on the network) and forms the structure of
                                            # the variable above from it. When the __init__ method is called __new__ is already finished processing the buffer.
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None): # __init__ method is used for handling object initialization. socket_buffer variable here is filled with the contents of "raw_buffer[0:20]" below in the script
                                            # __init__ here is used simply to give some human readable output for the protocol in use and the IP addresses.
        # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"} # this is a variable we created, is NOT inherited from Structure class.

        # human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src)) # this is a variable we created, is NOT inherited from Structure class. 
                                                                            # Converts an IP address, which is in 32-bit packed format to the popular human readable dotted-quad string format.
                                                                            # on the struct.pack method, "<" stands for little-endian format, and "L" for Long integer type. Read the following links for more info and better understanding:
        '''
        https://docs.python.org/2/library/struct.html
        https://pythontic.com/modules/socket/inet_ntoa
        So above inet_ntoa will look something like:
        socket.inet_ntoa(struct.pack("<L", 167772160))
        socket.inet_ntoa(\x7f\x00\x00\x01) which will return:
        192.168.1.1 or the corresponding dotted-quad string value to that binary representation.
        '''
        # self.src & self.dst variables are an IP stored as Decimal value (e.j 167772160). Read: https://stackoverflow.com/questions/5217732/using-inet-ntoa-function-in-python
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst)) # this is a variable we created, is NOT inherited from Structure class. 

        # human readable Protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except: # If it's not ICMP, TCP nor UDP protocols
            self.protocol = str(self.protocol_num)


if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP # Windows
else:
    socket_protocol = socket.IPPROTO_ICMP # Linux

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host,0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) # to include the IP headers in the captured traffic

if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON) # enable promiscous mode if platform is Windows

try:
    while True:
        # read in a packet
        raw_buffer = sniffer.recvfrom(65565)[0] # print only the packet contents. [1] would've been the host & port, i.e('192.168.1.134', 0#)

        # create an IP header from the first 20 bytes of the buffer
        ip_header = IP(raw_buffer[0:20])

        # print out the protocol that was detected and the hosts
        print "Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
# handle Ctrl-C
except KeyboardInterrupt:
    # if we're using Windows, turn off promiscous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
