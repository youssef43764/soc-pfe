import hashlib, json, logging, requests
log = logging.getLogger("SOC-AI.correlation")
_cache = {}

def correlate(alert: dict, ip_history: list, intel: dict) -> dict:
    key = hashlib.md5(json.dumps(alert, sort_keys=True).encode()).hexdigest()
    if key in _cache:
        return _cache[key]
    from config import OLLAMA_URL, MODEL
    rule = alert.get("rule", {}).get("description", "")
    mitre = alert.get("rule", {}).get("mitre", {}).get("id", [])
    count = len(ip_history)
    prompt = f"""SOC analyst. Reply ONLY in JSON, no text outside.
Alert: {rule}
MITRE: {mitre}
IP events count: {count}
Country: {intel.get('country')} ISP: {intel.get('isp')}
JSON:
{{"correlation_score":0,"attack_pattern":"","is_campaign":false,"risk_context":""}}"""
    try:
        r = requests.post(OLLAMA_URL,
            json={"model": MODEL, "prompt": prompt, "stream": False})
        r.raise_for_status()
        result = json.loads(r.json().get("response", "{}"))
        _cache[key] = result
        return result
    except Exception as e:
        log.warning(f"Corrélation indisponible : {e}")
    return {"correlation_score": 0, "attack_pattern": rule,
            "is_campaign": False, "risk_context": "indisponible"}
