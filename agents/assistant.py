import json, logging, requests
log = logging.getLogger("SOC-AI.assistant")

def ask(question: str, incident_context: dict, conversation_history: list = None) -> str:
    from config import OLLAMA_URL, MODEL
    history = conversation_history or []
    last = history[-2]["content"] if len(history) >= 2 else ""
    prompt = f"""Tu es un assistant SOC. Réponds en français, max 3 phrases.
Incident: IP={incident_context.get('ip')} priorité={incident_context.get('priority')}
Phase={incident_context.get('investigation',{}).get('attack_stage','')}
Résumé={incident_context.get('investigation',{}).get('executive_summary','')}
Dernière réponse: {last}
Question: {question}
Réponse:"""
    try:
        r = requests.post(OLLAMA_URL,
            json={"model": MODEL, "prompt": prompt, "stream": False})
        r.raise_for_status()
        return r.json().get("response", "").strip()
    except Exception as e:
        log.warning(f"Assistant indisponible : {e}")
        return "Assistant temporairement indisponible."
