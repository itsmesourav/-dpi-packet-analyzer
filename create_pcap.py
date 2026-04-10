from scapy.all import *

pkt = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="youtube.com"))

wrpcap("input.pcap", [pkt])

print("input.pcap created successfully!")