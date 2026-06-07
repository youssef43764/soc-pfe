import gzip, json, logging, os
log = logging.getLogger("SOC-AI.loader")

ALERTS_PATH = "/var/ossec/logs/alerts/"

def load_new_alerts() -> list:
    """
    Lit TOUTES les alertes (historique complet).
    La déduplication est gérée par le cache 'processed' dans soc_ai.py.
    """
    alertes = []
    for root, dirs, files in os.walk(ALERTS_PATH):
        for file in files:
            path = os.path.join(root, file)
            try:
                if file.endswith(".json"):
                    with open(path, "r", errors="ignore") as f:
                        for line in f:
                            try:
                                alertes.append(json.loads(line))
                            except:
                                continue
                elif file.endswith(".gz"):
                    with gzip.open(path, "rt", errors="ignore") as f:
                        for line in f:
                            try:
                                alertes.append(json.loads(line))
                            except:
                                continue
            except Exception as e:
                log.error(f"Impossible de lire {path} : {e}")
                continue
    log.info(f"📂 {len(alertes)} alertes chargées au total")
    return alertes
