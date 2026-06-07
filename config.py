# ==============================
# CONFIG GLOBALE SOC AI
# ==============================

# IP de ta VM SOC_AI où tourne Ollama
OLLAMA_URL = "http://192.168.56.105:11434/api/generate"
MODEL = "mranv/siem-llama-3.1:v1"

ALERTS_PATH = "/var/ossec/logs/alerts/"

# IP de ta VM pfSense
PFSENSE_IP = "192.168.56.254"
PFSENSE_USER = "admin"

ABUSE_API_KEY = "1b7dab52b57522ca21db8de55b95b3411ec131c903cc7799e81f04cc8bc83dbf002aa202e38ef063"
VT_API_KEY = "a4dec9b9684c216abc23f007b81bae127172625c588e0b28c218ded36f7f3886"

BRUTEFORCE_THRESHOLD = 20

TICKET_BACKEND = "local"
