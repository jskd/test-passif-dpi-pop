# test-passif-dpi

Petit DPI sur le protocole POP

## Comment lancer

usage: dpi-pop.py [-h] -i INPUT [-a] [-t] [-eth] [-ip] [-tcp]

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input file name
  -a, --all             Display all data
  -t, --time            Display time
  -eth                  Display eth data
  -ip                   Display ip data
  -tcp                  Display tcp data


Exemple:
* python3 dpi-pop.py -i pop3-sample-1.pcap
* python3 dpi-pop.py -i pop3-sample-2.pcap --all

# Equipe

* Egor KOCHKUROV
* Joaquim LEFRANC
* Jérôme SKODA

## Lib

pip3 install libpcap
pip3 install dpkt

https://pypi.python.org/pypi/libpcap
https://github.com/kbandla/dpkt

Examples parsing DPKT:

https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/
