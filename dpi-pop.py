# coding: utf-8
#
# Equipe:
# - Egor KOCHKUROV
# - Joaquim LEFRANC
# - Jérôme SKODA
#
# Inspiration :
# - https://dpkt.readthedocs.io/en/latest/print_http_requests.html
# - https://fr.wikipedia.org/wiki/Post_Office_Protocol
# - https://dpkt.readthedocs.io/en/latest/_modules/examples/print_icmp.html#mac_addr
# - https://docs.python.org/2/howto/argparse.html
#
import dpkt
import struct
import datetime
import re
import dpkt
import datetime
import socket
import sys
import argparse

from dpkt.compat import compat_ord

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

def print_timestamp(timestamp):
  """Print timestamp
  """
  print ('  Timestamp  : %s' % \
    (str(datetime.datetime.utcfromtimestamp(timestamp))))

def print_data(tcp):
  """ Print data of tcp
  """
  print ('  Data       : %s' % \
    (str(tcp.data)))

def print_ether_frame(eth):
  """ Print ethernet frame
  """
  print ('  Ether Frame: %s -> %s (%s)' % \
    (mac_addr(eth.src), mac_addr(eth.dst), eth.type))

def print_tcp_ip(ip):
  """ Print ip
  """
  # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
  do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
  more_fragments = bool(ip.off & dpkt.ip.IP_MF)
  fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
  print ('  IP         : %s -> %s (len=%d ttl=%d DF=%d MF=%d offset=%d)' % \
    (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))

def parse_and_print_pop(data):
  """ Parse and print POP3 protocole
      Based on: https://fr.wikipedia.org/wiki/Post_Office_Protocol
  """
  # rn escape
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
    ("[POP-C] USER", r"USER (.*)",
      "identification {value}", print_string),
    ("[POP-C] PASS", r"PASS (.*)",
      "authentification {value}", print_string),
    ("[POP-C] DELE", r"DELE (\d)",
      "efface le message spécifié", print_n_mess),
    ("[POP-C] LIST", r"LIST",
      "donne une liste des messages ainsi que la taille de chaque message : un numéro suivi de la taille en octets ;", print_no_arg),
    ("[POP-C] RETR", r"RETR (\d)",
      "récupère le message {n_mess}", print_n_mess),
    ("[POP-C] STAT", r"STAT",
      "indique le nombre de messages et la taille occupée par l'ensemble des messages", print_no_arg),
    ("[POP-C] TOP ", r"TOP (\d) (\d)",
      "affiche les {n_ligne} premières lignes du message {n_mess}.", print_comtop),
    ("[POP-C] APOP", r"APOP",
      "permet une authentification sécurisée (le mot de passe ne transite pas en clair)", print_no_arg),
    ("[POP-C] NOOP", r"NOOP",
      "ne rien faire, utile pour ne pas perdre la connexion et éviter un « délai d'attente dépassé »", print_no_arg),
    ("[POP-C] QUIT", r"QUIT",
      "quitter la session en cours", print_no_arg),
    ("[POP-C] RSET", r"RSET",
      "réinitialise complètement la session", print_no_arg),
    ("[POP-C] UIDL", r"UIDL",
      "affiche (pour un seul ou pour tous les messages) un identifiant unique qui ne varie pas entre chaque session", print_no_arg),
    ("[POP-C] CAPA", r"CAPA",
      "affiche les informations du serveur", print_no_arg),
    ("[POP-S] OK  ", r"\+OK(.*)",
      "Ok {value}", print_string),
    ("[POP-S] ERR ", r"-ERR(.*)",
      "Erreur {value}", print_string),
    ("[DATA]      ", r"(.*)",
      "(Premiere ligne) {value}", print_string)
  ]

  for label, regex, message, methode in commandes:
    matches = re.search(regex, data)
    if matches:
      methode(label, message, matches)
      break;

def dpi_pop(filename, d_time, d_ether, d_ip, d_tcp):
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
            parse_and_print_pop(tcp.data)

          except:
            print("[FAIL] DPI POP ERROR")
            pass

          if d_time:
            print_timestamp(timestamp)
          if d_ether:
            print_ether_frame(eth)
          if d_ip:
            print_tcp_ip(ip)
          if d_tcp:
            print_data(tcp)
          if d_time or d_ether or d_ip or d_tcp:
            print()

  f.close()

def main():
  parser = argparse.ArgumentParser(description='Petit DPI sur le protocole POP')
  parser.add_argument('-i',   '--input', help='Input file name',  required=True, type=str)
  parser.add_argument('-a',   '--all',   help='Display all data', action="store_true")
  parser.add_argument('-t',   '--time',  help='Display time',     action="store_true")
  parser.add_argument('-eth',            help='Display eth data', action="store_true")
  parser.add_argument('-ip',             help='Display ip data',  action="store_true")
  parser.add_argument('-tcp',            help='Display tcp data', action="store_true")
  args = parser.parse_args()
  dpi_pop( args.input , args.time or args.all, args.eth or args.all, args.ip or args.all, args.tcp or args.all)

if __name__ == "__main__":
  main()

# C'EST TERMINE! BONNE FETE DE FIN D'ANNEE
