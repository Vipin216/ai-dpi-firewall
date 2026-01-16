import csv
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP

CSV_FILE = "data/traffic.csv"

# write CSV header once
with open(CSV_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["time", "src_ip", "dst_ip", "protocol", "length"])

def packet_handler(packet):
    if IP in packet:
        proto = "OTHER"
        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"

        row = [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            packet[IP].src,
            packet[IP].dst,
            proto,
            len(packet)
        ]

        with open(CSV_FILE, "a", newline="") as f:
            csv.writer(f).writerow(row)

        print(row)

sniff(iface="eth0", prn=packet_handler, store=False)
