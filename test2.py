# coding: utf-8

# Inspiration : https://dpkt.readthedocs.io/en/latest/print_http_requests.html

import dpkt
import struct

with open("pop3.pcap", "rb") as f:
	pcap = dpkt.pcap.Reader(f)

	for ts, buf in pcap:

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

			if  len(tcp.data) > 0:
				print(tcp.data)
				print("\n")
	f.close()
