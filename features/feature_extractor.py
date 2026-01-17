import csv
from collections import defaultdict
from datetime import datetime

INPUT_FILE = "data/dpi_traffic.csv"
OUTPUT_FILE = "data/features.csv"

TIME_WINDOW = 10  


windows = defaultdict(lambda: {
    "packet_count": 0,
    "unique_src": set(),
    "unique_dst": set(),
    "http_count": 0,
    "dns_count": 0,
    "syn_count": 0
})

def get_window(ts):
    return int(ts.timestamp() // TIME_WINDOW * TIME_WINDOW)

with open(INPUT_FILE, newline="") as f:
    reader = csv.DictReader(f)

    for row in reader:
        ts = datetime.strptime(row["time"], "%Y-%m-%d %H:%M:%S")
        window = get_window(ts)

        stats = windows[window]
        stats["packet_count"] += 1
        stats["unique_src"].add(row["src_ip"])
        stats["unique_dst"].add(row["dst_ip"])

        if row["protocol"] == "HTTP":
            stats["http_count"] += 1
        elif row["protocol"] == "DNS":
            stats["dns_count"] += 1

        if "SYN" in row["details"]:
            stats["syn_count"] += 1


with open(OUTPUT_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "window_start",
        "packet_count",
        "unique_src_ips",
        "unique_dst_ips",
        "http_requests",
        "dns_queries",
        "syn_packets"
    ])

    for window, stats in windows.items():
        writer.writerow([
            window,
            stats["packet_count"],
            len(stats["unique_src"]),
            len(stats["unique_dst"]),
            stats["http_count"],
            stats["dns_count"],
            stats["syn_count"]
        ])

print("Feature extraction complete → data/features.csv")
