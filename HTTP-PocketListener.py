import scapy.all as scapy
from scapy_http import http

def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=analyze_packets)

def analyze_packets(packet):
    packet.show()
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.RAW):
            packet[scapy.RAW].load


sniff_packets("eth0")