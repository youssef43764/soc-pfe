import json, logging, os, uuid, requests
from datetime import datetime
log = logging.getLogger("SOC-AI.ticketing")
TICKETS_FILE = "/root/tickets.json"

def _load():
    if not os.path.exists(TICKETS_FILE): return []
    try:
        with open(TICKETS_FILE) as f: return json.load(f)
    except: return []

def _save(tickets):
    with open(TICKETS_FILE, "w") as f: json.dump(tickets, f, indent=2, ensure_ascii=False)

def _local(ticket):
    tickets = _load(); tickets.append(ticket); _save(tickets)
    log.info(f"📋 Ticket local : {ticket['id']}"); return ticket["id"]

def _thehive(ticket):
    from config import THEHIVE_URL, THEHIVE_API_KEY
    sev = {"P1":3,"P2":2,"P3":1,"P4":1}
    try:
        r = requests.post(f"{THEHIVE_URL}/api/case",
            headers={"Authorization":f"Bearer {THEHIVE_API_KEY}","Content-Type":"application/json"},
            json={"title":ticket["title"],"description":ticket["description"],
                  "severity":sev.get(ticket["priority"],1),"tags":ticket.get("tags",[]),"tlp":2}, timeout=10)
        r.raise_for_status()
        cid = r.json().get("id", ticket["id"])
        log.info(f"📋 Ticket TheHive : {cid}"); return cid
    except Exception as e:
        log.error(f"TheHive indisponible ({e}) → fallback local"); return _local(ticket)

def _jira(ticket):
    from config import JIRA_URL, JIRA_USER, JIRA_TOKEN, JIRA_PROJECT
    pmap = {"P1":"Critical","P2":"High","P3":"Medium","P4":"Low"}
    try:
        r = requests.post(f"{JIRA_URL}/rest/api/2/issue",
            auth=(JIRA_USER, JIRA_TOKEN),
            json={"fields":{"project":{"key":JIRA_PROJECT},"summary":ticket["title"],
                  "description":ticket["description"],"issuetype":{"name":"Incident"},
                  "priority":{"name":pmap.get(ticket["priority"],"Medium")}}}, timeout=10)
        r.raise_for_status()
        key = r.json().get("key", ticket["id"])
        log.info(f"📋 Ticket Jira : {key}"); return key
    except Exception as e:
        log.error(f"Jira indisponible ({e}) → fallback local"); return _local(ticket)

def create_ticket(ip, priority, investigation, correlation, playbook, intel) -> str:
    from config import TICKET_BACKEND
    now = datetime.now().isoformat()
    tid = str(uuid.uuid4())[:8].upper()
    title = f"[{priority}] {correlation.get('attack_pattern','Incident')} — IP {ip} ({intel.get('country','?')})"
    desc = f"""## Résumé\n{investigation.get('executive_summary','N/A')}

## Détails
- **IP** : {ip} | **Pays/ISP** : {intel.get('country','?')} / {intel.get('isp','?')}
- **Phase** : {investigation.get('attack_stage','?')} | **TTPs** : {', '.join(investigation.get('ttps',[]))}
- **Assets** : {', '.join(investigation.get('impacted_assets',['Aucun']))}

## Hypothèses
{chr(10).join('- '+h for h in investigation.get('hypotheses',[]))}

## Actions immédiates
{chr(10).join(f"- [{a.get('owner','?').upper()}] {a.get('action','')}" for a in playbook.get('immediate_actions',[]))}

---
*Généré par SOC AI — {now}*"""
    ticket = {"id":tid,"title":title,"description":desc,"priority":priority,
              "ip":ip,"created_at":now,"status":"open",
              "tags":[f"priority:{priority}",f"country:{intel.get('country','?')}",
                      correlation.get("attack_pattern","unknown")] + investigation.get("ttps",[])}
    if TICKET_BACKEND == "thehive": return _thehive(ticket)
    elif TICKET_BACKEND == "jira": return _jira(ticket)
    else: return _local(ticket)
