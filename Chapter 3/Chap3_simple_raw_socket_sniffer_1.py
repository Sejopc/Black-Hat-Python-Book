import socket
import os

# host to listen on
# host = "192.168.1.134" # IP of our Windows7 - Python Virtual Box Machine (on My ASUS Laptop)
host = "192.168.100.8" # IP of our MacBookPro Machine

# create a raw socket and bind it to the public interface
if os.name == "nt": # Windows
    socket_protocol = socket.IPPROTO_IP
else: # Linux
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host,0))

# we want the IP headers included in the capture
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# if we are using Windows, we need to send an IOCTL (socket INPUT/OUTPUT Control) to set up promiscous mode
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON) # The SIO_RCVALL control code enables a socket to receive all IPv4 or IPv6 packets passing through a network interface.

# read in a single packet
print sniffer.recvfrom(65565)

# if we're using Windows, turn off promiscous mode
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

