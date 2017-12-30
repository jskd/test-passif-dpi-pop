# test-passif-dpi

Script de DPI sur le protocole POP

## Usage

```
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
```

## Exemple d'utilisation

* python3 dpi-pop.py -i pop3-sample-1.pcap
* python3 dpi-pop.py -i pop3-sample-2.pcap --all

# Equipe

* Egor KOCHKUROV
* Joaquim LEFRANC
* Jérôme SKODA

## Paquet python requis

* pip3 install libpcap
* pip3 install dpkt
