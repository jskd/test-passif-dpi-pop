# coding: utf-8

import dpkt

with open("pop3.pcap", "rb") as f:
	pcap = dpkt.pcap.Reader(f)

	for ts, buf in pcap:
		print(buf)
		print("\n")
