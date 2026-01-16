import csv
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw

CSV_FILE = "data/dpi_traffic.csv"


with open(CSV_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "time",
        "src_ip",
        "dst_ip",
        "protocol",
        "details"
    ])

def packet_handler(packet):
    if IP not in packet:
        return

    src = packet[IP].src
    dst = packet[IP].dst
    proto = "OTHER"
    details = ""

    #TCP PACKETS
    if TCP in packet:
        proto = "TCP"
        flags = packet[TCP].flags

        if flags & 0x02:  # SYN
            details = "TCP SYN (connection attempt)"
        elif flags & 0x10:  # ACK
            details = "TCP ACK"

        #HTTP DETECTION 
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            if Raw in packet:
                payload = packet[Raw].load.decode(errors="ignore")
                if payload.startswith(("GET", "POST")):
                    proto = "HTTP"
                    details = payload.split("\r\n")[0]

    #DNS PACKETS
    elif UDP in packet and DNS in packet and packet[DNS].qr == 0:
        proto = "DNS"
        details = packet[DNSQR].qname.decode()

    
    if proto != "OTHER":
        row = [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            src,
            dst,
            proto,
            details
        ]

        with open(CSV_FILE, "a", newline="") as f:
            csv.writer(f).writerow(row)

        print(row)


sniff(iface="eth0", prn=packet_handler, store=False)
