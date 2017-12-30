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

  data= str(data, 'utf-8').rstrip();

  #print methode
  print_no_arg = lambda label, message, matches: print("%s" % label, ":", message)
  print_n_mess = lambda label, message, matches: print("%s" % label, ":", message
    .replace("{n_mess}" , matches.group(1)) )
  print_comtop = lambda label, message, matches: print("%s" % label, ":", message
    .replace("{n_mess}" , matches.group(1))
    .replace("{n_ligne}", matches.group(2)) )
  print_string = lambda label, message, matches:   print("%s" %  label, ":", message
    .replace("{value}"  , matches.group(1)) )

  commandes = [
    ("[POP-C] USER", "USER (.*)",
      "identification {value}", print_string),
    ("[POP-C] PASS", "PASS (.*)",
      "authentification {value}", print_string),
    ("[POP-C] DELE", "DELE (\d)",
      "efface le message spécifié", print_n_mess),
    ("[POP-C] LIST", "LIST",
      "donne une liste des messages ainsi que la taille de chaque message : un numéro suivi de la taille en octets ;", print_no_arg),
    ("[POP-C] RETR", "RETR (\d)",
      "récupère le message {n_mess}", print_n_mess),
    ("[POP-C] STAT", "STAT",
      "indique le nombre de messages et la taille occupée par l'ensemble des messages", print_no_arg),
    ("[POP-C] TOP ", "TOP (\d) (\d)",
      "affiche les {n_ligne} premières lignes du message {n_mess}.", print_comtop),
    ("[POP-C] APOP", "APOP",
      "permet une authentification sécurisée (le mot de passe ne transite pas en clair)", print_no_arg),
    ("[POP-C] NOOP", "NOOP",
      "ne rien faire, utile pour ne pas perdre la connexion et éviter un « délai d'attente dépassé »", print_no_arg),
    ("[POP-C] QUIT", "QUIT",
      "quitter la session en cours", print_no_arg),
    ("[POP-C] RSET", "RSET",
      "réinitialise complètement la session", print_no_arg),
    ("[POP-C] UIDL", "UIDL",
      "affiche (pour un seul ou pour tous les messages) un identifiant unique qui ne varie pas entre chaque session", print_no_arg),
    ("[POP-C] CAPA", "CAPA",
      "affiche les informations du serveur", print_no_arg),
    ("[POP-S] OK",   "\+OK (.*)",
      "Réponse ok {value}", print_string)
  ]

  for label, regex, message, methode in commandes:
    matches = re.search(regex, data)
    if matches:
      methode(label, message, matches)
      break;
    else:
      print("\"" + data + "\"")

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

          try:
            parse_pop(tcp.data)
          except:
            pass
          #print_tcp_data(timestamp, ip, eth, tcp)
          #print()




  f.close()



dpi_pop("pop3-2.pcap")
