from scapy.all import sniff

def start_sniffing(callback):
    print("Sniffing started...")
    sniff(filter="port 53 or port 443", prn=callback, store=False)