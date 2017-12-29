# coding: utf-8

# Inspiration : https://dpkt.readthedocs.io/en/latest/print_http_requests.html

import dpkt
import struct
import datetime

import re

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

# https://dpkt.readthedocs.io/en/latest/_modules/examples/print_icmp.html#mac_addr
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

def print_tcp_data(timestamp, ip, eth, tcp):

  # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
  do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
  more_fragments = bool(ip.off & dpkt.ip.IP_MF)
  fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

  print ('Data:       %s' % \
    (str(tcp.data)))
  print ('Timestamp:    %s' % \
    (str(datetime.datetime.utcfromtimestamp(timestamp))))
  print ('Ethernet Frame: %s -> %s (%s)' % \
    (mac_addr(eth.src), mac_addr(eth.dst), eth.type))
  print ('IP:       %s -> %s (len=%d ttl=%d DF=%d MF=%d offset=%d)' % \
    (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))










# based on https://fr.wikipedia.org/wiki/Post_Office_Protocol
def parse_pop(data):

  commandes = [
    (b"DELE", "efface le message spécifié"),
    (b"LIST", "donne une liste des messages ainsi que la taille de chaque message : un numéro suivi de la taille en octets ;"),
    (b"RETR", "récupère le message indiqué"),
    (b"STAT", " indique le nombre de messages et la taille occupée par l'ensemble des messages"),
    (b"TOP", "affiche les premières lignes du message."),
    (b"APOP", "permet une authentification sécurisée (le mot de passe ne transite pas en clair)"),
    (b"NOOP", "ne rien faire, utile pour ne pas perdre la connexion et éviter un « délai d'attente dépassé »"),
    (b"QUIT", "quitter la session en cours"),
    (b"RSET", "réinitialise complètement la session"),
    (b"UIDL", "affiche (pour un seul ou pour tous les messages) un identifiant unique qui ne varie pas entre chaque session"),
    (b"CAPA", "affiche les informations du serveur"),
  ]


  for regex, message in commandes:
    matches = re.search(regex, data)
    if matches:
      print("[POP] %s" % regex.decode("utf-8"), ":", message )
      break;




'''
  regex = b"RETR (\d)"
  matches = re.search(regex, data)
  if matches:
    print("[POP] récupère le message %s" % int(matches.group(1), 10) )
'''



def dpi_pop(filename):
  with open(filename, "rb") as f:
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

        if len(tcp.data) > 0:

          parse_pop(tcp.data)

          #print_tcp_data(timestamp, ip, eth, tcp)
          #print()




  f.close()



dpi_pop("pop3.pcap")
