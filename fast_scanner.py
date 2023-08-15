import os
import sys
import scapy.all as scapy
from scapy.all import ARP, Ether, srp
import socket
from tabulate import tabulate

def get_assigned_ip_and_interface():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    assigned_ip = s.getsockname()[0]
    interface = scapy.get_working_if()
    s.close()
    return assigned_ip, interface

def get_vendor(mac):
    try:
        mac_prefix = mac[:8].upper()  # Convert to uppercase for consistency
        nmap_mac_prefixes_file = "mac_vendor.txt"
        
        with open(nmap_mac_prefixes_file, 'r') as f:
            for line in f:
                if line.startswith(mac_prefix):
                    return line.strip().split('\t')[1]
    except:
        pass
    return " "

def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return " "

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Please run this script as root.")
        sys.exit(1)

    assigned_ip, interface = get_assigned_ip_and_interface()
    ip_range = assigned_ip + "/24"
    
    arp_layer = ARP(pdst=ip_range)
    broadcast = "FF:FF:FF:FF:FF:FF"
    ether_layer = Ether(dst=broadcast)

    packet = ether_layer / arp_layer

    ans, _ = srp(packet, iface=interface, timeout=2)

    data = []

    for _, rcv in ans:
        ip = rcv[ARP].psrc
        mac = rcv[Ether].src
        vendor = get_vendor(mac)
        hostname = get_hostname(ip)
        data.append([ip,mac])
#        data.append([ip, mac, vendor, hostname])

#    headers = ['IP Address', 'MAC Address', 'Vendor', 'Hostname']
    headers = [' IP Address', ' MAC Adress']
    table = tabulate(data, headers=headers, tablefmt='pipe')
    print(table)

