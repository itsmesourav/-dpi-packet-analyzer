from scapy.all import *

def parse_packet(pkt):
    data = {}

    if pkt.haslayer(IP):
        ip = pkt[IP]
        data["src_ip"] = ip.src
        data["dst_ip"] = ip.dst

    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        data["protocol"] = "UDP"
        data["src_port"] = udp.sport
        data["dst_port"] = udp.dport

    elif pkt.haslayer(TCP):
        tcp = pkt[TCP]
        data["protocol"] = "TCP"
        data["src_port"] = tcp.sport
        data["dst_port"] = tcp.dport

    # DNS Detection
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        domain = pkt[DNSQR].qname.decode(errors="ignore")
        data["domain"] = domain.strip(".")

    return data