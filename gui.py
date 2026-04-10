import tkinter as tk
from scapy.all import rdpcap
from parser import parse_packet
from rules import RuleEngine
from datetime import datetime

rules = RuleEngine()

def add_domain():
    domain = entry.get()
    if domain:
        rules.block_domain(domain)
        text_box.insert(tk.END, f"✅ Added to block list: {domain}\n\n")
        entry.delete(0, tk.END)

def run_analysis():
    text_box.delete("1.0", tk.END)

    packets = rdpcap("input.pcap")

    seen_domains = set()   # ✅ avoid duplicates

    for pkt in packets:
        info = parse_packet(pkt)

        if info:
            domain = info.get("domain")

            # skip duplicate domains
            if domain and domain in seen_domains:
                continue

            if domain:
                seen_domains.add(domain)

            time_now = datetime.now().strftime("%H:%M:%S")

            output = f"""
⏰ Time       : {time_now}
📦 Packet Info
Source IP   : {info.get("src_ip")}
Destination : {info.get("dst_ip")}
Protocol    : {info.get("protocol")}
Domain      : {info.get("domain")}
"""

            # ✅ FIXED (no duplicate insert)
            if not rules.allow(info):
                output += f"🚫 BLOCKED DOMAIN: {info.get('domain')}\n"
                output += "\n==============================\n"
                text_box.insert(tk.END, output, "blocked")
            else:
                output += f"✅ ALLOWED DOMAIN: {info.get('domain')}\n"
                output += "\n==============================\n"
                text_box.insert(tk.END, output)

    text_box.tag_config("blocked", foreground="red")


# -------- GUI DESIGN --------
root = tk.Tk()
root.title("DPI Packet Analyzer")
root.geometry("750x550")

# Title
title = tk.Label(root, text="DPI Packet Analyzer", font=("Arial", 16, "bold"))
title.pack(pady=10)

# Input field
entry = tk.Entry(root, width=40)
entry.pack(pady=5)

# Add button
add_btn = tk.Button(root, text="Add Domain to Block", command=add_domain)
add_btn.pack(pady=5)

# Run button
run_btn = tk.Button(root, text="Run Analysis", command=run_analysis)
run_btn.pack(pady=10)

# Text box
text_box = tk.Text(root, font=("Courier", 10))
text_box.pack(expand=True, fill="both", padx=10, pady=10)

root.mainloop()