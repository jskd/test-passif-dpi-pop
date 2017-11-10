# coding: utf-8

import dpkt
import struct

with open("pop3.pcap", "rb") as f:
	pcap = dpkt.pcap.Reader(f)

	for ts, buf in pcap:
		eth = dpkt.ethernet.Ethernet(buf)
		ip = eth.data
		tcp = ip.data

		if  len(tcp.data) > 0:
			print(tcp.data)
			print("\n")
	f.close()