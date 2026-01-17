import csv

RULE_ALERTS = "data/alerts.csv"    
AI_SCORES = "data/ai_scores.csv"    
OUTPUT_FILE = "data/final_decisions.csv"

ai_risk_map = {}

with open(AI_SCORES, newline="") as f:
    reader = csv.DictReader(f)

    for row in reader:
        window = row["window_start"]
        raw_ai_risk = row.get("ai_risk", "").strip()

        
        if raw_ai_risk == "":
            ai_risk = 0.0
        else:
            try:
                ai_risk = float(raw_ai_risk)
            except ValueError:
                ai_risk = 0.0

        ai_risk_map[window] = ai_risk


def fuse_decision(rule_risk, ai_risk):
    
    rationale = []

    
    if rule_risk >= 70:
        return 90, "HIGH", "Rule-based detection triggered"

    if ai_risk >= 80:
        return 85, "HIGH", "AI anomaly score very high"

    
    combined = 0.6 * rule_risk + 0.4 * ai_risk

    if rule_risk >= 30:
        rationale.append("Rule-based suspicion")

    if ai_risk >= 40:
        rationale.append("AI-based anomaly")

    if combined >= 70:
        severity = "HIGH"
    elif combined >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return round(combined, 2), severity, "; ".join(rationale)


with open(RULE_ALERTS, newline="") as f:
    reader = csv.DictReader(f)

    with open(OUTPUT_FILE, "w", newline="") as out:
        writer = csv.writer(out)

        writer.writerow([
            "window_start",
            "rule_risk",
            "ai_risk",
            "final_risk",
            "severity",
            "rationale"
        ])

        for row in reader:
            window = row["window_start"]
            rule_risk = int(row["risk_score"])
            ai_risk = ai_risk_map.get(window, 0.0)

            final_risk, severity, rationale = fuse_decision(rule_risk, ai_risk)

            writer.writerow([
                window,
                rule_risk,
                ai_risk,
                final_risk,
                severity,
                rationale
            ])

print("Hybrid fusion complete → data/final_decisions.csv")
