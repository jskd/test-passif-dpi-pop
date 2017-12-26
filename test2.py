# coding: utf-8

# Inspiration : https://dpkt.readthedocs.io/en/latest/print_http_requests.html

import dpkt
import struct
import datetime


import dpkt
import datetime
import socket
from dpkt.compat import compat_ord


# https://dpkt.readthedocs.io/en/latest/_modules/examples/print_icmp.html#mac_addr
def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)




with open("pop3.pcap", "rb") as f:
	pcap = dpkt.pcap.Reader(f)

	for timestamp, buf in pcap:

		# Unpack the Ethernet frame (mac src/dst, ethertype)
		eth = dpkt.ethernet.Ethernet(buf)

		# Make sure the Ethernet data contains an IP packet
		if not isinstance(eth.data, dpkt.ip.IP):
			print ('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
			continue

		# Now grab the data within the Ethernet frame (the IP packet)
		ip = eth.data

		# Check for TCP in the transport layer
		if isinstance(ip.data, dpkt.tcp.TCP):

			eth = dpkt.ethernet.Ethernet(buf)
			tcp = ip.data

			# Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
			do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
			more_fragments = bool(ip.off & dpkt.ip.IP_MF)
			fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

			if  len(tcp.data) > 0:
				print ('Data:           %s' % \
					(str(tcp.data)))
				print ('Timestamp:      %s' % \
					(str(datetime.datetime.utcfromtimestamp(timestamp))))
				print ('Ethernet Frame: %s -> %s (%s)' % \
					(mac_addr(eth.src), mac_addr(eth.dst), eth.type))
				print ('IP:             %s -> %s (len=%d ttl=%d DF=%d MF=%d offset=%d)' % \
					(inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))

				print()

	f.close()
