import logging, requests
log = logging.getLogger("SOC-AI.enrichment")
CACHE_IP = {}

def enrich_ip(ip):
    if ip in CACHE_IP:
        return CACHE_IP[ip]

    from config import ABUSE_API_KEY, VT_API_KEY

    result = {
        "ip": ip, "abuse_score": 0, "vt_malicious": 0,
        "country": "unknown", "isp": "unknown", "threat_score": 0
    }

    # AbuseIPDB
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            timeout=5
        )
        r.raise_for_status()
        d = r.json().get("data", {})
        result["abuse_score"] = d.get("abuseConfidenceScore", 0)
        result["country"]     = d.get("countryCode", "unknown")
        result["isp"]         = d.get("isp", "unknown")
        log.info("AbuseIPDB %s → score=%d pays=%s", ip, result["abuse_score"], result["country"])
    except Exception as e:
        log.warning("AbuseIPDB erreur pour %s : %s", ip, e)

    # VirusTotal
    try:
        r = requests.get(
            "https://www.virustotal.com/api/v3/ip_addresses/{}".format(ip),
            headers={"x-apikey": VT_API_KEY},
            timeout=5
        )
        r.raise_for_status()
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        result["vt_malicious"] = stats.get("malicious", 0)
        log.info("VirusTotal %s → malicious=%d", ip, result["vt_malicious"])
    except Exception as e:
        log.warning("VirusTotal erreur pour %s : %s", ip, e)

    result["threat_score"] = int((result["abuse_score"] + result["vt_malicious"] * 10) / 2)
    CACHE_IP[ip] = result
    return result
