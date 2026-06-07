import json, logging, requests
log = logging.getLogger("SOC-AI.investigation")

def investigate(alert: dict, ip_history: list, correlation: dict, intel: dict) -> dict:
    from config import OLLAMA_URL, MODEL
    rule = alert.get("rule", {}).get("description", "")
    mitre = alert.get("rule", {}).get("mitre", {}).get("id", [])
    prompt = f"""SOC analyst. Reply ONLY in JSON, no text outside.
Alert: {rule}
MITRE: {mitre}
Pattern: {correlation.get('attack_pattern','')}
Events: {len(ip_history)}
JSON:
{{"attack_stage":"","ttps":[],"impacted_assets":[],"severity_assessment":"low","executive_summary":""}}"""
    try:
        r = requests.post(OLLAMA_URL,
            json={"model": MODEL, "prompt": prompt, "stream": False})
        r.raise_for_status()
        return json.loads(r.json().get("response", "{}"))
    except Exception as e:
        log.warning(f"Investigation indisponible : {e}")
    return {"attack_stage": "unknown", "ttps": mitre if isinstance(mitre, list) else [],
            "impacted_assets": [], "severity_assessment": "high",
            "executive_summary": f"Attaque détectée : {rule}",
            "hypotheses": [], "timeline": []}
