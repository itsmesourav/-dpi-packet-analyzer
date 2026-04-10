from scapy.all import rdpcap
from parser import parse_packet
from rules import RuleEngine

print("Reading PCAP file...\n")

packets = rdpcap("input.pcap")

rules = RuleEngine()
rules.block_domain("youtube.com")

for pkt in packets:
    info = parse_packet(pkt)

    if info:
        print("------ Packet Detected ------")
        print("Source IP:", info.get("src_ip"))
        print("Destination IP:", info.get("dst_ip"))
        print("Protocol:", info.get("protocol"))
        print("Domain:", info.get("domain"))

        # Save log
        with open("log.txt", "a") as f:
            f.write(str(info) + "\n")

        if not rules.allow(info):
            print("🚫 BLOCKED DOMAIN:", info.get("domain"))

        print("-----------------------------\n")