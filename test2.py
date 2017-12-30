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

  simple_print  = lambda label, message, matches:   print("%s" % label, ":", message )
  print_N_mess = lambda label, message, matches:   print("%s" % label, ":",  message.replace("{n_mess}", str(int(matches.group(1), 10))  ))
  print_TOP = lambda label, message, matches:   print("%s" % label, ":", message.replace("{n_mess}", str(int(matches.group(1), 10))  ).replace("{n_ligne}", str(int(matches.group(2), 10))  ))
  print_str = lambda label, message, matches:   print("%s" %  label, ":", message.replace("{value}", str(matches.group(1))))

  commandes = [
    ("[POP] USER", b"USER (.+)",
      "identification {value}", print_str),
    ("[POP] PASS", b"PASS (.+)",
      "authentification {value}", print_str),
    ("[POP] DELE", b"DELE (\d)",
      "efface le message spécifié", print_N_mess),
    ("[POP] LIST", b"LIST",
      "donne une liste des messages ainsi que la taille de chaque message : un numéro suivi de la taille en octets ;", simple_print),
    ("[POP] RETR", b"RETR (\d)",
      "récupère le message {n_mess}", print_N_mess),
    ("[POP] STAT", b"STAT",
      "indique le nombre de messages et la taille occupée par l'ensemble des messages", simple_print),
    ("[POP] TOP ", b"TOP (\d) (\d)",
      "affiche les {n_ligne} premières lignes du message {n_mess}.", print_TOP),
    ("[POP] APOP", b"APOP",
      "permet une authentification sécurisée (le mot de passe ne transite pas en clair)", simple_print),
    ("[POP] NOOP", b"NOOP",
      "ne rien faire, utile pour ne pas perdre la connexion et éviter un « délai d'attente dépassé »", simple_print),
    ("[POP] QUIT", b"QUIT",
      "quitter la session en cours", simple_print),
    ("[POP] RSET", b"RSET",
      "réinitialise complètement la session", simple_print),
    ("[POP] UIDL", b"UIDL",
      "affiche (pour un seul ou pour tous les messages) un identifiant unique qui ne varie pas entre chaque session", simple_print),
    ("[POP] CAPA", b"CAPA",
      "affiche les informations du serveur", simple_print),
  ]



  for label, regex, message, methode in commandes:
    matches = re.search(regex, data)
    if matches:
      methode(label, message, matches)
      break;
    #print(data)




'''
  regex = b"RETR (\d)"
  matches = re.search(regex, data)
  if matches:
    print("[POP] récupère le message %s" %  )
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



dpi_pop("pop3-2.pcap")
