import csv

INPUT_FILE = "data/features.csv"
OUTPUT_FILE = "data/alerts.csv"

def calculate_risk(row):
    risk = 0
    reasons = []

    packet_count = int(row["packet_count"])
    unique_dst = int(row["unique_dst_ips"])
    http = int(row["http_requests"])
    dns = int(row["dns_queries"])
    syn = int(row["syn_packets"])

    
    if packet_count > 80:
        risk += 30
        reasons.append("High packet rate")

    
    if syn > 40:
        risk += 40
        reasons.append("Excessive TCP SYN packets")

    
    if unique_dst > 30:
        risk += 30
        reasons.append("High number of unique destinations")

   
    if dns > 20 and http < 3:
        risk += 25
        reasons.append("Abnormal DNS activity")

    
    risk = min(risk, 100)

    return risk, "; ".join(reasons)

with open(INPUT_FILE, newline="") as f:
    reader = csv.DictReader(f)

    with open(OUTPUT_FILE, "w", newline="") as out:
        writer = csv.writer(out)
        writer.writerow([
            "window_start",
            "risk_score",
            "severity",
            "reasons"
        ])

        for row in reader:
            risk, reasons = calculate_risk(row)

            if risk >= 70:
                severity = "HIGH"
            elif risk >= 30:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            writer.writerow([
                row["window_start"],
                risk,
                severity,
                reasons
            ])

print("Rule-based detection complete → data/alerts.csv")
