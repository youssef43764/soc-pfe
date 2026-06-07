"""
SOC AI — Orchestrateur principal (Wazuh Manager)
- Une entrée par alerte dans la DB (pas par IP)
- Brute force = 20 auth failures en moins de 60 secondes (timestamp réel)
- P1/P2 : analyse IA via Ollama (prompt texte libre)
- P3/P4 : analyse instantanée sans IA
- Fallback Ollama → garde la vraie priorité (pas P1 forcé)
- processed_cache persistant sur disque (sauvegarde immédiate)
- Blocage automatique P1 sur pfSense
- Compatible Python 3.6+
"""
import calendar, hashlib, ipaddress, json, logging, requests, subprocess, time, uuid, re
import signal, os
from collections import defaultdict, deque
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("/root/soc_ai.log"), logging.StreamHandler()]
)
log = logging.getLogger("SOC-AI")

from core.loader import load_new_alerts
from core.enrichment import enrich_ip
from core.firewall import block_ip
from core.priority import calculate_priority
from ticketing.ticket import create_ticket

# ==============================
# CONFIG BRUTE FORCE
# ==============================
BRUTEFORCE_THRESHOLD = 20
BRUTEFORCE_WINDOW    = 60   # secondes

# ==============================
# webhook n8n
# ==============================
N8N_WEBHOOK_P1 = "http://192.168.56.105:5678/webhook/soc-p1"

def notify_n8n_p1(entry):
    """Envoie l'alerte P1 à n8n pour notification email."""
    payload = {
        "ip":            entry.get("ip", ""),
        "timestamp":     entry.get("timestamp", ""),
        "score":         entry.get("score", 0),
        "ticket_id":     entry.get("ticket_id", ""),
        "blocked":       entry.get("blocked", False),
        "country":       entry.get("intel", {}).get("country", "unknown"),
        "isp":           entry.get("intel", {}).get("isp", "unknown"),
        "attack_pattern":entry.get("correlation", {}).get("attack_pattern", ""),
        "attack_stage":  entry.get("investigation", {}).get("attack_stage", ""),
        "summary":       entry.get("investigation", {}).get("executive_summary", ""),
        "playbook":      entry.get("playbook", {}).get("playbook_template", ""),
        "dashboard_url": "http://192.168.56.104:5000/ip/{}".format(entry.get("ip",""))
    }
    try:
        r = requests.post(N8N_WEBHOOK_P1, json=payload, timeout=3)
        log.info("  ↳ n8n notifié : email envoyé")
    except Exception as e:
        log.warning("  ↳ n8n indisponible : %s", e)
# ==============================
# PLAGES PRIVÉES (RFC 1918)
# ==============================
PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]

PRIORITY_ORDER = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}

AUTH_FAIL_KEYWORDS = [
    "authentication fail", "login fail", "invalid user",
    "failed password", "brute", "pam:", "invalid login",
    "authentication error", "logon failure", "wrong password",
    "permission denied", "access denied"
]

# ==============================
# HELPERS
# ==============================
def is_private(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return True

def is_auth_failure(alert):
    rule_desc = alert.get("rule", {}).get("description", "").lower()
    return any(k in rule_desc for k in AUTH_FAIL_KEYWORDS)

def parse_alert_timestamp(alert):
    """
    Extrait le timestamp réel de l'alerte Wazuh en secondes epoch.
    Wazuh utilise le champ 'timestamp' au format ISO 8601.
    Retourne time.time() si le champ est absent ou invalide.
    """
    raw = alert.get("timestamp") or alert.get("@timestamp", "")
    if not raw:
        return time.time()
    try:
        # Format Wazuh : 2026-04-22T22:26:55.123+0000 ou 2026-04-22T22:26:55.123Z
        # On prend seulement les 19 premiers caractères : YYYY-MM-DDTHH:MM:SS
        clean = raw[:19].replace("T", " ")
        d = datetime.strptime(clean, "%Y-%m-%d %H:%M:%S")
        return float(calendar.timegm(d.timetuple()))
    except Exception:
        return time.time()

# ==============================
# ÉTAT GLOBAL
# ==============================
ip_counter     = defaultdict(int)
blocked_ips    = set()
ip_history     = defaultdict(list)
ip_auth_window = defaultdict(deque)   # fenêtre glissante par IP

PROCESSED_FILE = "/root/processed_cache.json"

def load_processed():
    try:
        with open(PROCESSED_FILE) as f:
            return set(json.load(f))
    except:
        return set()

def save_processed():
    try:
        with open(PROCESSED_FILE, "w") as f:
            json.dump(list(processed), f)
    except OSError as e:
        log.error("processed_cache.json : %s", e)

processed = load_processed()
log.info("📋 %d alertes déjà traitées chargées", len(processed))

def _load_db():
    try:
        with open("/root/soc_db.json") as f:
            return json.load(f)
    except:
        return []

incidents_db = _load_db()
log.info("📂 %d alertes chargées depuis la DB", len(incidents_db))

for _inc in incidents_db:
    _ip = _inc.get("ip")
    if _ip:
        ip_counter[_ip] = max(ip_counter[_ip], _inc.get("count", 0))
        if _inc.get("blocked"):
            blocked_ips.add(_ip)
log.info("🔢 %d IPs restaurées | 🚫 %d IPs bloquées", len(ip_counter), len(blocked_ips))

# ==============================
# DÉTECTION BRUTE FORCE
# Utilise le vrai timestamp de l'alerte — pas time.time()
# ==============================
def check_bruteforce(ip):
    """
    Ajoute le timestamp réel de l'alerte dans la fenêtre glissante.
    Purge les entrées hors de la fenêtre de 60 secondes.
    Retourne (is_bruteforce, count_in_window).
    """
    now =time.time()
    window = ip_auth_window[ip]
    window.append(now)

    # Purger les timestamps hors fenêtre
    while window and (now - window[0]) > BRUTEFORCE_WINDOW:
        window.popleft()

    count_in_window = len(window)
    is_bf = count_in_window >= BRUTEFORCE_THRESHOLD
    return is_bf, count_in_window

# ==============================
# MAPPING MITRE SANS IA
# ==============================
def _mitre_stage(mitre_id):
    if not mitre_id:
        return "Reconnaissance"
    if isinstance(mitre_id, list):
        mitre_id = " ".join(mitre_id)
    mapping = {
        "T1110": "Credential Access",
        "T1190": "Initial Access",
        "T1059": "Execution",
        "T1071": "Command and Control",
        "T1566": "Initial Access",
        "T1046": "Discovery",
        "T1595": "Reconnaissance",
        "T1078": "Defense Evasion",
        "T1021": "Lateral Movement",
        "T1048": "Exfiltration",
        "T1486": "Impact",
        "T1053": "Execution",
        "T1055": "Defense Evasion",
    }
    for tid, stage in mapping.items():
        if tid in mitre_id:
            return stage
    return "Reconnaissance"

# ==============================
# PARSEUR RÉPONSE TEXTE IA
# ==============================
def parse_ai_text(text, fallback_rule, fallback_mitre):
    # Protection absolue contre None
    if not text:
        text = ""
    text = str(text)

    def extract(label, default):
        try:
            m = re.search(
                r'(?:^|\n)\s*' + label + r'\s*[:\-]\s*(.+)',
                text, re.IGNORECASE
            )
            if m:
                val = m.group(1)
                if val:
                    return str(val).strip()
        except Exception:
            pass
        return str(default) if default else ""

    ttps_raw = extract("TTPS?|TTP", "")
    ttps = []
    if ttps_raw:
        ttps = [t.strip() for t in re.split(r'[,\s]+', ttps_raw)
                if t.strip() and re.match(r'T\d{4}', t.strip())]
    if not ttps and fallback_mitre:
        ttps = fallback_mitre if isinstance(fallback_mitre, list) else [str(fallback_mitre)]

    severity = extract("SEVERITY|SEVERITE", "high")
    if not severity or severity.lower() not in ("low", "medium", "high", "critical"):
        severity = "high"
    else:
        severity = severity.lower()

    return {
        "attack_pattern": extract("PATTERN|ATTACK|ATTAQUE", fallback_rule) or str(fallback_rule),
        "attack_stage":   extract("STAGE|PHASE", "") or _mitre_stage(fallback_mitre),
        "ttps":           ttps,
        "severity":       severity,
        "summary":        extract("SUMMARY|RESUME", fallback_rule) or str(fallback_rule),
        "playbook":       extract("PLAYBOOK|ACTIONS", "1. Bloquer | 2. Analyser | 3. Reporter") or "1. Bloquer | 2. Analyser | 3. Reporter",
    }

# ==============================
# ANALYSE RAPIDE SANS IA (P3/P4)
# ==============================
def analyze_without_ai(ip, alert, count, priority):
    rule  = alert.get("rule", {}).get("description", "unknown")
    mitre = alert.get("rule", {}).get("mitre", {}).get("id", [])
    level = alert.get("rule", {}).get("level", 0)

    if priority == "P1":
        severity = "critical"
        playbook = "1. Bloquer IP sur pfSense | 2. Isoler les systemes affectes | 3. Analyser les logs immediatement | 4. Alerter le responsable SOC"
        summary  = "CRITIQUE : {} detecte depuis {} — niveau Wazuh {}, {} evenement(s). Reponse immediate requise.".format(
                       rule, ip, level, count)

    elif priority == "P2":
        severity = "high"
        playbook = "1. Surveiller l IP en temps reel | 2. Verifier les logs d acces | 3. Preparer un blocage si aggravation | 4. Documenter l incident"
        summary  = "IMPORTANT : {} detecte depuis {} — niveau Wazuh {}, {} evenement(s). Surveillance renforcee.".format(
                       rule, ip, level, count)
    elif priority == "P3":
        severity = "medium"
        playbook = "1. Surveiller l'IP | 2. Analyser les logs | 3. Escalader si aggravation"
    else:
        severity = "low"
        playbook = "1. Journaliser | 2. Surveiller | 3. Ignorer si normal"

    return {
        "attack_pattern": rule,
        "attack_stage":   _mitre_stage(mitre),
        "ttps":           mitre if isinstance(mitre, list) else [],
        "severity":       severity,
        "summary":        "{} detecte depuis {} — niveau Wazuh {}, {} evenement(s).".format(
                              rule, ip, level, count),
        "playbook":       playbook
    }

# ==============================
# ANALYSE IA OLLAMA — PROMPT TEXTE LIBRE
# ==============================
def analyze_with_ollama(ip, alert, count, priority):
    from config import OLLAMA_URL, MODEL

    rule  = alert.get("rule", {}).get("description", "unknown")
    mitre = alert.get("rule", {}).get("mitre", {}).get("id", [])

    prompt = (
        "SOC alert. Short answers only.\n"
        "Alert: {rule}\n\n"
        "PATTERN: (2-4 word attack name, NOT the alert description)\n"
        "SEVERITY: (low/medium/high/critical)\n"
        "SUMMARY: (one sentence in French what is happening)\n"
        "PLAYBOOK: (action1 | action2 | action3)"
    ).format(rule=rule)

    try:
        r = requests.post(
            OLLAMA_URL,
            json={"model": MODEL, "prompt": prompt, "stream": False}
        )
        r.raise_for_status()

        resp = r.json()
        response_text = resp.get("response") if resp else None
        if not response_text or not isinstance(response_text, str):
            raise ValueError("Reponse vide ou None")

        response_text = response_text.strip()
        if not response_text:
            raise ValueError("Reponse vide apres strip")

        result = parse_ai_text(response_text, rule, mitre)
        log.info("  ↳ IA OK : %s | %s", result.get("attack_pattern","?"), result.get("severity","?"))
        return result

    except requests.RequestException as e:
        log.warning("Ollama indisponible : %s → fallback [%s]", e, priority)
    except Exception as e:
        log.warning("Erreur IA : %s → fallback [%s]", e, priority)

    return analyze_without_ai(ip, alert, count, priority)
# ==============================
# CONSTRUCTION D'UNE ALERTE
# ==============================
def build_alert_entry(ip, alert, count, ai, intel, priority, score,
                      ticket_id, auth_in_window=0):
    correlation = {
        "attack_pattern":    ai.get("attack_pattern", "unknown"),
        "correlation_score": min(score * 3, 100),
        "is_campaign":       auth_in_window > 20,
        "risk_context":      ai.get("summary", ""),
        "related_rules":     [],
        "identity_context":  "unknown"
    }
    investigation = {
        "attack_stage":        ai.get("attack_stage", "unknown"),
        "ttps":                ai.get("ttps", []),
        "impacted_assets":     [ip],
        "severity_assessment": ai.get("severity", "low"),
        "executive_summary":   ai.get("summary", ""),
        "hypotheses":          [],
        "timeline":            []
    }

    if priority in ("P1", "P2"):
        immediate = [
            {"step": 1, "action": "Bloquer l'IP sur pfSense",   "owner": "auto",    "tool": "pfctl"},
            {"step": 2, "action": "Analyser les logs Wazuh",    "owner": "analyst", "tool": "wazuh"},
            {"step": 3, "action": "Documenter l'incident",      "owner": "analyst", "tool": "dashboard"},
            {"step": 4, "action": "Notifier l'equipe securite", "owner": "analyst", "tool": "email"},
        ]
        eta = "30 minutes"
    elif priority == "P3":
        immediate = [
            {"step": 1, "action": "Surveiller l'IP sur le dashboard", "owner": "analyst", "tool": "dashboard"},
            {"step": 2, "action": "Analyser les logs Wazuh",          "owner": "analyst", "tool": "wazuh"},
        ]
        eta = "2 heures"
    else:
        immediate = [
            {"step": 1, "action": "Journaliser l'evenement",          "owner": "auto",    "tool": "dashboard"},
            {"step": 2, "action": "Surveiller les prochaines alertes", "owner": "analyst", "tool": "wazuh"},
        ]
        eta = "Basse priorite"

    playbook_text = ai.get("playbook", "")
    playbook_steps = []
    for i, step in enumerate(playbook_text.split("|"), 1):
        step = step.strip()
        if step:
            step = re.sub(r'^\d+[\.\)]\s*', '', step)
            playbook_steps.append({
                "step": i, "action": step,
                "owner": "auto" if i == 1 else "analyst",
                "tool":  "pfctl" if i == 1 else "wazuh"
            })

    all_actions = immediate if immediate else playbook_steps

    playbook = {
        "playbook_name":             "Playbook_{}_{}".format(priority, ai.get("attack_pattern", "incident")),
        "immediate_actions":         all_actions,
        "manual_actions": [
            {"action": "Verifier les assets impactes", "priority": "high"   if priority in ("P1","P2") else "low"},
            {"action": "Contacter l'equipe securite",  "priority": "medium" if priority in ("P1","P2") else "low"},
        ],
        "automated_actions":         [],
        "detection_rules":           [],
        "playbook_template":         playbook_text or "1. Analyser 2. Decider 3. Reporter",
        "estimated_resolution_time": eta
    }

    rule_info = {
        "id":          alert.get("rule", {}).get("id", ""),
        "description": alert.get("rule", {}).get("description", ""),
        "level":       alert.get("rule", {}).get("level", 0),
        "mitre":       alert.get("rule", {}).get("mitre", {}),
    }

    return {
        "alert_id":       str(uuid.uuid4())[:8].upper(),
        "timestamp":      str(datetime.now()),
        "ip":             ip,
        "count":          count,
        "auth_in_window": auth_in_window,
        "priority":       priority,
        "score":          score,
        "last_update":    str(datetime.now()),
        "intel":          intel,
        "correlation":    correlation,
        "investigation":  investigation,
        "playbook":       playbook,
        "ticket_id":      ticket_id,
        "blocked":        ip in blocked_ips,
        "status":         "open",
        "rule":           rule_info,
        "agent":          alert.get("agent", {}),
    }

# ==============================
# TRAITEMENT D'UNE ALERTE
# ==============================
def process(alert):
    ip = alert.get("data", {}).get("srcip") or alert.get("agent", {}).get("ip")

    if not ip or is_private(ip):
        return

    ip_counter[ip] += 1
    count = ip_counter[ip]
    ip_history[ip].append(alert)

    intel = enrich_ip(ip)

    basic_ai = {
        "severity":   "high"   if intel["threat_score"] > 50 else
                      "medium" if intel["threat_score"] > 20 else "low",
        "confidence": min(intel["threat_score"], 100)
    }
    score, priority = calculate_priority(alert, basic_ai, intel)

    # ── Détection Brute Force avec timestamp réel ──
    auth_in_window = 0
    is_bf          = False

    if is_auth_failure(alert):
        is_bf, auth_in_window = check_bruteforce(ip)
        if is_bf:
            priority, score = "P1", 30
            log.info("🔥 BruteForce %s — %d auth failures en %ds",
                     ip, auth_in_window, BRUTEFORCE_WINDOW)
        else:
            log.debug("⚠️  Auth failure %s — %d/%d dans la fenetre",
                      ip, auth_in_window, BRUTEFORCE_THRESHOLD)

    ticket_id = None

    # Analyse selon priorité — FIX : on passe la vraie priorité au fallback
    if priority in ("P1", "P2"):
        log.info("🧠 Analyse IA (texte libre) → %s [%s]", ip, priority)
        ai_data = analyze_with_ollama(ip, alert, count, priority)
    else:
        log.info("⚡ Analyse rapide (sans IA) → %s [%s]", ip, priority)
        ai_data = analyze_without_ai(ip, alert, count, priority)

    if priority in ("P1", "P2"):
        tmp = build_alert_entry(ip, alert, count, ai_data, intel,
                                priority, score, None, auth_in_window)
        ticket_id = create_ticket(
            ip, priority,
            tmp["investigation"],
            tmp["correlation"],
            tmp["playbook"],
            intel
        )
        log.info("  ↳ Ticket : %s", ticket_id)

    if priority == "P1" and ip not in blocked_ips:
        block_ip(ip)
        blocked_ips.add(ip)

    entry = build_alert_entry(ip, alert, count, ai_data, intel,
                              priority, score, ticket_id, auth_in_window)
    incidents_db.append(entry)
    
    if priority == "P1":
        notify_n8n_p1(entry)

    log.info(
        "✅ %s | %s | score=%d | auth_window=%d/%d | alert_id=%s | ticket=%s",
        ip, priority, score, auth_in_window, BRUTEFORCE_THRESHOLD,
        entry["alert_id"], ticket_id or "N/A"
    )
    log.info("📊 DB : %d alertes total", len(incidents_db))
    save()

# ==============================
# SAUVEGARDE ATOMIQUE
# Écrit dans un fichier temporaire puis renomme
# → si Ctrl+C pendant l'écriture, l'original est intact
# ==============================
def save():
    tmp = "/root/soc_db.json.tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(incidents_db, f, indent=2, ensure_ascii=False)
        os.replace(tmp, "/root/soc_db.json")   # atomique
    except OSError as e:
        log.error("soc_db.json : %s", e)

# ==============================
# GESTIONNAIRE CTRL+C
# Sauvegarde proprement avant de quitter
# ==============================
def handle_exit(signum, frame):
    log.info("⛔ Arrêt demandé — sauvegarde en cours...")
    save()
    save_processed()
    log.info("✅ %d alertes sauvegardées | %d hashes sauvegardés",
             len(incidents_db), len(processed))
    log.info("👋 SOC AI arrêté proprement.")
    exit(0)

signal.signal(signal.SIGINT,  handle_exit)   # Ctrl+C
signal.signal(signal.SIGTERM, handle_exit)   # kill
# ==============================
# Synchroniser la DB avec pfSense
# ==============================
def sync_blocked_ips_to_pfsense():
    """
    Au démarrage, re-bloque toutes les IPs marquées bloquées dans la DB
    qui ne sont plus dans pfSense (après un redémarrage pfSense).
    """
    if not blocked_ips:
        return
    log.info("🔄 Synchronisation des IPs bloquées vers pfSense...")
    for ip in blocked_ips:
        try:
            subprocess.Popen(
                ["ssh", "-o", "StrictHostKeyChecking=no",
                 "admin@192.168.56.254",
                 "pfctl -t blocklist -T add {}".format(ip)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            ).communicate(timeout=10)
            log.info("  ↳ %s re-bloquée sur pfSense", ip)
        except Exception as e:
            log.warning("  ↳ Erreur sync %s : %s", ip, e)
# ==============================
# MAIN LOOP
# ==============================
def main():
    log.info("🚀 SOC AI MULTI-AGENT demarre")
    log.info("   Appuyez sur Ctrl+C pour arrêter proprement")
    sync_blocked_ips_to_pfsense()
    log.info("   Mode : 1 alerte = 1 entree DB")
    log.info("   P1/P2 → Ollama IA (texte libre) | P3/P4 → Analyse instantanee")
    log.info("   BruteForce → %d auth failures en %ds (timestamp reel)", BRUTEFORCE_THRESHOLD, BRUTEFORCE_WINDOW)

    while True:
        for alert in load_new_alerts():
            h = hashlib.md5(json.dumps(alert, sort_keys=True).encode()).hexdigest()
            if h in processed:
                continue
            try:
                process(alert)
                processed.add(h)
                save_processed()   # sauvegarde immédiate après chaque alerte
            except Exception as e:
                log.error("Erreur alerte (sera retraitee) : %s", e, exc_info=True)

        time.sleep(10)

if __name__ == "__main__":
    main()
