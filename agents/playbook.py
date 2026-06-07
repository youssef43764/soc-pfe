import json, logging, requests
log = logging.getLogger("SOC-AI.playbook")

def generate_playbook(alert: dict, investigation: dict, correlation: dict, priority: str) -> dict:
    from config import OLLAMA_URL, MODEL
    prompt = f"""SOC analyst. Reply ONLY in JSON, no text outside.
Priority: {priority}
Stage: {investigation.get('attack_stage','')}
TTPs: {investigation.get('ttps',[])}
Pattern: {correlation.get('attack_pattern','')}
JSON:
{{"playbook_name":"","immediate_actions":[{{"step":1,"action":"","owner":"auto","tool":""}}],"manual_actions":[{{"action":"","priority":"high"}}],"estimated_resolution_time":""}}"""
    try:
        r = requests.post(OLLAMA_URL,
            json={"model": MODEL, "prompt": prompt, "stream": False})
        r.raise_for_status()
        return json.loads(r.json().get("response", "{}"))
    except Exception as e:
        log.warning(f"Playbook indisponible : {e}")
    # Playbook par défaut selon priorité
    return {
        "playbook_name": f"Playbook_{priority}_{correlation.get('attack_pattern','default')}",
        "immediate_actions": [
            {"step": 1, "action": "Bloquer l'IP sur pfSense", "owner": "auto", "tool": "pfctl"},
            {"step": 2, "action": "Isoler les assets impactés", "owner": "analyst", "tool": "wazuh"},
        ],
        "manual_actions": [
            {"action": "Vérifier les logs complets", "priority": "high"},
            {"action": "Contacter l'équipe sécurité", "priority": "medium"},
        ],
        "automated_actions": [],
        "detection_rules": [],
        "playbook_template": f"PLAYBOOK {priority}\n1. Block IP\n2. Investigate\n3. Report",
        "estimated_resolution_time": "30 minutes"
    }
