def mitre_priority(mitre_id) -> int:
    if not mitre_id:
        return 0
    if isinstance(mitre_id, list):
        mitre_id = " ".join(mitre_id)
    mapping = {"T1110": 10, "T1059": 8, "T1190": 9, "T1071": 6, "T1566": 7}
    for tid, score in mapping.items():
        if tid in mitre_id:
            return score
    return 3

def calculate_priority(alert: dict, ai: dict, intel: dict) -> tuple:
    level = int(alert.get("rule", {}).get("level", 0))
    mitre_id = alert.get("rule", {}).get("mitre", {}).get("id", [])
    score = level + mitre_priority(mitre_id)
    severity = ai.get("severity", "low")
    if severity == "high": score += 5
    elif severity == "medium": score += 3
    score += int(intel.get("threat_score", 0) * 0.1)
    if int(ai.get("confidence", 0)) > 80: score += 2
    if score >= 20: return score, "P1"
    elif score >= 14: return score, "P2"
    elif score >= 8: return score, "P3"
    else: return score, "P4"
