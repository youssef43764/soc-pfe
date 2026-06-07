# 🛡️ SOC AI — Security Operations Center

<div align="center">

![SOC AI](https://img.shields.io/badge/SOC-AI%20Platform-00e5ff?style=for-the-badge&logo=shield&logoColor=black)
![Python](https://img.shields.io/badge/Python-3.6-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Dashboard-000000?style=for-the-badge&logo=flask&logoColor=white)
![Wazuh](https://img.shields.io/badge/Wazuh-SIEM-005571?style=for-the-badge)
![Ollama](https://img.shields.io/badge/Ollama-mranv%2Fsiem--llama--3.1-black?style=for-the-badge)
![pfSense](https://img.shields.io/badge/pfSense-Firewall-212121?style=for-the-badge)

**Plateforme SOC complète — Détection, Analyse IA et Blocage automatique des menaces.**
100% on-premise, aucune donnée ne quitte l'infrastructure.

</div>

---

## 📋 Table des matières

- [Architecture](#-architecture)
- [VMs et IPs](#-vms-et-ips)
- [Fonctionnalités](#-fonctionnalités)
- [Structure du projet](#-structure-du-projet)
- [Installation complète](#-installation-complète)
  - [VM 1 — Wazuh Manager](#vm-1--wazuh-manager-19216856104)
  - [VM 2 — SOC AI / Ollama](#vm-2--soc-ai--ollama-19216856105)
  - [VM 3 — pfSense](#vm-3--pfsense-192168562540)
  - [VM 4 — Kali Linux](#vm-4--kali-linux-attaques)
- [Configuration](#-configuration)
- [Lancement du système](#-lancement-du-système)
- [Accès au dashboard](#-accès-au-dashboard)
- [Comptes par défaut](#-comptes-par-défaut)
- [Pipeline de traitement](#-pipeline-de-traitement)
- [Niveaux de priorité](#-niveaux-de-priorité)
- [Dépannage](#-dépannage)

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        VirtualBox — Host-Only 192.168.56.0/24         │
│                                                                        │
│  ┌─────────────────┐   Attaque    ┌──────────────────────────────┐   │
│  │  Kali Linux     │ ──────────► │      WAZUH MANAGER           │   │
│  │  (attaquant)    │             │      192.168.56.104           │   │
│  │                 │             │                               │   │
│  │ 192.168.56.107  │             │  ┌─────────────────────────┐ │   │
│  │ 192.168.56.103  │             │  │     soc_ai.py           │ │   │
│  │ 192.168.0.145   │             │  │  Pipeline d'analyse     │ │   │
│  └─────────────────┘             │  │  SIEM + SOC AI engine   │ │   │
│                                  │  └──────────┬──────────────┘ │   │
│  ┌─────────────────┐             │             │                 │   │
│  │  Analyste SOC   │  Dashboard  │  ┌──────────▼──────────────┐ │   │
│  │  Navigateur     │◄──:5000──── │  │    dashboard.py         │ │   │
│  │                 │             │  │    Flask :5000          │ │   │
│  └─────────────────┘             │  └─────────────────────────┘ │   │
│                                  └──────────────┬────────────────┘   │
│                                                 │                     │
│              ┌──────────────────────────────────┤                     │
│              │                                  │                     │
│              ▼                                  ▼                     │
│  ┌───────────────────────┐       ┌─────────────────────────┐         │
│  │   SOC-AI VMs          │       │       pfSense           │         │
│  │   192.168.56.105      │       │       192.168.56.254    │         │
│  │                       │       │                         │         │
│  │  Ollama               │       │  Pare-feu               │         │
│  │  mranv/siem-llama-3.1 │       │  Blocage IP (pfctl)     │         │
│  └───────────────────────┘       └─────────────────────────┘         │
│                                                                        │
└──────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼ (carte NAT séparée)
                        ┌───────────────────────┐
                        │        Internet        │
                        │  AbuseIPDB            │
                        │  VirusTotal           │
                        └───────────────────────┘
```

---

## 🖥️ VMs et IPs

| VM | Rôle | IP | OS | RAM | CPU |
|---|---|---|---|---|---|
| **Wazuh Manager** | SIEM + Pipeline SOC AI + Dashboard | `192.168.56.104` | CentOS/RHEL 7 | 4 Go min | 2 |
| **SOC-AI VMs** | Ollama LLM (`mranv/siem-llama-3.1`) | `192.168.56.105` | Ubuntu 22.04 | 8 Go min | 4 |
| **pfSense** | Pare-feu / Blocage IP automatique | `192.168.56.254` | pfSense 2.7+ | 1 Go | 1 |
| **Kali Linux** | Machine attaquante (tests) | `192.168.56.107` / `.103` / `192.168.0.145` | Kali 2024 | 2 Go | 2 |

> **Réseau VirtualBox** : toutes les VMs sur le même adaptateur **Host-Only** `192.168.56.0/24`.
> Le Wazuh Manager a une **carte NAT supplémentaire** pour accéder à AbuseIPDB et VirusTotal.

---

## ✨ Fonctionnalités

| # | Fonctionnalité | Détail |
|---|---|---|
| 🧠 | **Analyse IA locale** | `mranv/siem-llama-3.1` via Ollama — aucune donnée ne sort du réseau |
| ⚡ | **Détection brute force** | 20 échecs d'auth en 60s → P1 automatique |
| 🌐 | **Threat Intelligence** | AbuseIPDB + VirusTotal — enrichissement avec cache mémoire |
| 🚫 | **Blocage pfSense** | SSH automatique → `pfctl -t blocklist -T add <ip>` |
| 📋 | **Ticketing & Playbooks** | Ticket + playbook SOAR pour chaque P1/P2 |
| 💬 | **Chatbot analyste** | Assistant IA contextuel dans chaque alerte |
| 📊 | **Dashboard temps réel** | Stats, graphes Chart.js, Top 10 IPs, auto-refresh 60s |
| 💻 | **Terminal web** | Bash intégré avec streaming SSE (admin uniquement) |
| 🔐 | **Auth multi-rôles** | Admin + Analyste SOC, sessions Flask persistantes |
| 📄 | **Rapports** | Export HTML filtrable par période |

---

## 📁 Structure du projet

```
/root/
├── soc_ai.py                  # Orchestrateur — pipeline d'analyse principal
├── dashboard.py               # Serveur Flask — interface web port 5000
├── config.py                  # ⚠️ Configuration (clés API, IPs) — NE PAS commiter
├── config.example.py          # Template de configuration (sans les vraies clés)
│
├── core/
│   ├── __init__.py
│   ├── loader.py              # Lecture incrémentale alerts.json Wazuh
│   ├── enrichment.py          # AbuseIPDB + VirusTotal
│   ├── firewall.py            # Blocage IP pfSense via SSH
│   └── priority.py            # Calcul score P1→P4
│
├── agents/
│   ├── __init__.py
│   ├── correlation.py         # Structure corrélation
│   ├── investigation.py       # Structure investigation + TTPs MITRE
│   ├── playbook.py            # Playbook SOAR
│   └── assistant.py           # Chatbot analyste (appel Ollama à la demande)
│
├── ticketing/
│   ├── __init__.py
│   └── ticket.py              # Création tickets locaux
│
├── templates/
│   ├── landing.html           # Page d'accueil publique
│   ├── login.html             # Authentification
│   ├── index.html             # Dashboard principal
│   ├── closed.html            # Alertes fermées
│   ├── terminal.html          # Terminal web (admin)
│   ├── profile.html           # Profil utilisateur
│   ├── admin_users.html       # Gestion utilisateurs
│   ├── rapport.html           # Rapport d'incidents
│   └── unauthorized.html      # Page 403
│
# ── Fichiers auto-générés (non commités) ──
├── soc_db.json                # Alertes actives
├── soc_db_closed.json         # Alertes fermées
├── processed_cache.json       # Hashes alertes déjà traitées
├── tickets.json               # Tickets créés
├── users.json                 # Utilisateurs (mots de passe hashés SHA-256)
└── soc_ai.log                 # Logs du pipeline
```

---

## 🚀 Installation complète

### VM 1 — Wazuh Manager `192.168.56.104`

> Cette VM fait tourner Wazuh, le pipeline `soc_ai.py` et le dashboard Flask.

**1.1 — Cloner le projet**
```bash
cd /root
git clone https://github.com/TON_USERNAME/soc-ai.git .
```

**1.2 — Installer les dépendances Python**
```bash
# Installer pip si absent
yum install python3-pip -y

pip3 install flask requests
```

**1.3 — Configurer**
```bash
cp config.example.py config.py
nano config.py
# Remplir les IPs, clés API, modèle Ollama
```

**1.4 — Ouvrir les ports nécessaires**
```bash
# Port dashboard
iptables -I INPUT -p tcp --dport 5000 -j ACCEPT

# Vérifier que Wazuh tourne
/var/ossec/bin/ossec-control status
```

**1.5 — Configurer la carte réseau NAT pour internet**

Dans VirtualBox (VM éteinte) :
- Réseau → Carte 2 → Activer → Mode : **NAT**

Puis dans la VM :
```bash
# Activer la carte NAT (généralement eth1)
ip link set eth1 up
dhclient eth1

# Tester
ping 8.8.8.8
curl -s https://api.abuseipdb.com | head -3
```

**1.6 — Configurer SSH sans mot de passe vers pfSense**
```bash
# Générer la clé SSH
ssh-keygen -t rsa -b 2048 -f /root/.ssh/id_rsa -N ""

# Afficher la clé publique (à coller dans pfSense)
cat /root/.ssh/id_rsa.pub

# Tester après configuration pfSense
ssh -o StrictHostKeyChecking=no admin@192.168.56.254 "echo OK"
```

---

### VM 2 — SOC AI / Ollama `192.168.56.105`

> Cette VM fait tourner le LLM `mranv/siem-llama-3.1` via Ollama.

**2.1 — Installer Ollama**
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**2.2 — Configurer Ollama pour écouter sur toutes les interfaces**
```bash
nano /etc/systemd/system/ollama.service
```
Ajouter dans la section `[Service]` :
```ini
Environment="OLLAMA_HOST=0.0.0.0:11434"
```
```bash
systemctl daemon-reload
systemctl restart ollama
systemctl enable ollama

# Vérifier
ss -tlnp | grep 11434
# → doit afficher 0.0.0.0:11434 (PAS 127.0.0.1)
```

**2.3 — Télécharger le modèle**
```bash
# Modèle principal du projet
ollama pull mranv/siem-llama-3.1

# Modèles alternatifs (si siem-llama trop lent)
ollama pull phi3:mini      # 3.8B — 4 Go RAM
ollama pull mistral        # 7B   — 8 Go RAM
ollama pull tinyllama      # 1.1B — 2 Go RAM (le plus rapide)
```

**2.4 — Ouvrir le port 11434**
```bash
ufw allow 11434
# ou si ufw absent :
iptables -I INPUT -p tcp --dport 11434 -j ACCEPT
```

**2.5 — Tester depuis Wazuh Manager**
```bash
# Sur 192.168.56.104
curl http://192.168.56.105:11434
# → "Ollama is running"

# Tester le modèle (chronométrer)
time curl -s http://192.168.56.105:11434/api/generate \
  -d '{"model":"mranv/siem-llama-3.1","prompt":"say hi","stream":false}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('response',''))"
```

---

### VM 3 — pfSense `192.168.56.254`

**3.1 — Activer SSH**

Interface web pfSense (`http://192.168.56.254`) :
- **System → Advanced → Admin Access**
- ✅ Enable Secure Shell → Save

**3.2 — Ajouter la clé SSH du Wazuh Manager**

- **System → User Manager → admin → Edit**
- Section **Authorized SSH Keys** → coller le contenu de `/root/.ssh/id_rsa.pub`
- Save

**3.3 — Créer la table de blocage**

- **Firewall → Aliases → Add**
  - Name : `blocklist`
  - Type : `Host(s)`
  - Save & Apply

- **Firewall → Rules → WAN → Add**
  - Action : Block
  - Source : `blocklist`
  - Save & Apply

**3.4 — Vérifier le blocage**
```bash
# Depuis Wazuh Manager
ssh admin@192.168.56.254 "pfctl -t blocklist -T show"
```

---

### VM 4 — Kali Linux (attaques)

```bash
# Installer les outils
sudo apt update
sudo apt install -y nmap hydra hping3 nikto

# ── Attaque P1 — Brute force SSH (20 échecs → blocage auto) ──
hydra -l root -P /usr/share/wordlists/rockyou.txt \
  -t 4 ssh://192.168.56.104

# ── Attaque P2 — Scan agressif ──
nmap -A -sV -T4 192.168.56.104

# ── Attaque P3 — Scan discret ──
nmap -sS -T2 192.168.56.104

# ── Attaque P4 — Ping / sondage basique ──
ping -c 5 192.168.56.104
```

---

## ⚙️ Configuration

Éditer `/root/config.py` avec tes vraies valeurs :

```python
# ── Ollama ──────────────────────────────────────────────
OLLAMA_URL = "http://192.168.56.105:11434/api/generate"
MODEL      = "mranv/siem-llama-3.1"

# ── pfSense ─────────────────────────────────────────────
PFSENSE_IP   = "192.168.56.254"
PFSENSE_USER = "admin"

# ── Threat Intelligence ─────────────────────────────────
# AbuseIPDB  → https://www.abuseipdb.com/register
# VirusTotal → https://www.virustotal.com/gui/join-us
ABUSE_API_KEY = "TON_API_ABUSEIPDB"
VT_API_KEY    = "TON_API_VIRUSTOTAL"

# ── Wazuh ───────────────────────────────────────────────
ALERTS_PATH = "/var/ossec/logs/alerts/"

# ── Brute force ─────────────────────────────────────────
BRUTEFORCE_THRESHOLD = 20   # échecs en moins de WINDOW secondes
BRUTEFORCE_WINDOW    = 60   # fenêtre glissante en secondes

# ── Ticketing ───────────────────────────────────────────
TICKET_BACKEND = "local"
```

---

## ▶️ Lancement du système

```bash
# ── Sur VM Wazuh Manager (192.168.56.104) ──

# Terminal 1 — Pipeline d'analyse (laisser tourner en permanence)
cd /root
python3 soc_ai.py

# Terminal 2 — Dashboard web
python3 dashboard.py
```

```bash
# ── Sur VM SOC AI (192.168.56.105) ──

# S'assurer qu'Ollama tourne
systemctl status ollama
ollama ps   # voir les modèles chargés

# Si pas démarré
systemctl start ollama
```

---

## 🌐 Accès au dashboard

```
http://192.168.56.104:5000
```

| Page | URL | Accès |
|---|---|---|
| Landing page | `/` | Public |
| Login | `/login` | Public |
| Dashboard | `/dashboard` | Tous les connectés |
| Vue par IP | `/ip/<adresse>` | Tous les connectés |
| Alertes fermées | `/closed` | Tous les connectés |
| Rapport | `/rapport` | Tous les connectés |
| Profil | `/profile` | Tous les connectés |
| Gestion users | `/admin/users` | Admin uniquement |
| Terminal web | `/terminal` | Admin uniquement |

---

## 👤 Comptes par défaut

| Identifiant | Mot de passe | Rôle |
|---|---|---|
| `admin` | `admin123` | Administrateur (accès complet + terminal) |
| `analyst` | `analyst123` | SOC Analyste (dashboard + alertes + chatbot) |

> ⚠️ **Changer immédiatement ces mots de passe** via `http://192.168.56.104:5000/profile`

---

## 🔄 Pipeline de traitement

```
/var/ossec/logs/alerts/alerts.json   ← Wazuh écrit ici
         │
         ▼  (toutes les 10 secondes)
    loader.py
    Déduplication MD5 → processed_cache.json
         │
         ▼
    enrichment.py
    AbuseIPDB + VirusTotal → threat_score
    (cache mémoire — pas de double appel par IP)
         │
         ▼
    priority.py
    score = niveau_wazuh + MITRE + threat_intel
         │
         ├── Brute force ? 20 échecs / 60s → force P1
         │
         ├── P1 / P2 ──► analyze_with_ollama()
         │                mranv/siem-llama-3.1
         │                timeout 30s
         │                fallback → analyze_without_ai() si indisponible
         │
         └── P3 / P4 ──► analyze_without_ai()
                          règles statiques, instantané
                │
                ▼
         build_incident()
         assemble corrélation + investigation + playbook
                │
         ┌──────┴──────┐
         ▼             ▼
    ticket.py      firewall.py (P1 seulement)
    tickets.json   SSH → pfSense → pfctl -t blocklist -T add <ip>
         │
         ▼
    soc_db.json   ← sauvegarde immédiate
         │
         ▼
    dashboard.py  ← Flask lit et affiche
```

---

## 🚦 Niveaux de priorité

| Priorité | Score | Exemple réel | Actions |
|---|---|---|---|
| 🔴 **P1** | ≥ 20 | `hydra` brute force SSH depuis 192.168.56.103 | IA + Ticket + **Blocage pfSense** |
| 🟠 **P2** | 14–19 | `nmap -A` scan agressif depuis Kali | IA + Ticket |
| 🟢 **P3** | 8–13 | 3 erreurs de mot de passe SSH espacées | Règles statiques + Log |
| ⚫ **P4** | < 8 | Connexion SSH réussie, ping | Log uniquement |

### Calcul du score

```
score = niveau_wazuh (0-15)
      + MITRE  : T1110 +10 | T1190 +9 | T1059 +8 | T1566 +7 | autres +3
      + sévérité IA : high +5 | medium +3
      + threat_score AbuseIPDB × 0.1  (max +10)
      + confidence IA > 80 → +2
```

---

## 🔧 Dépannage

### Ollama timeout / lent

```bash
# Sur VM SOC AI (192.168.56.105)
ollama ps                    # modèle chargé en mémoire ?
systemctl restart ollama
ollama pull mranv/siem-llama-3.1

# Tester la vitesse
time curl -s http://localhost:11434/api/generate \
  -d '{"model":"mranv/siem-llama-3.1","prompt":"hi","stream":false}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('response',''))"

# Si trop lent → utiliser tinyllama
# nano /root/config.py → MODEL = "tinyllama"
```

### Blocage pfSense échoue (Errno 12 — mémoire)

```bash
free -h                  # vérifier RAM disponible
pkill -f soc_ai.py       # redémarrer pour libérer la mémoire
python3 /root/soc_ai.py
```

### Dashboard inaccessible

```bash
ss -tlnp | grep 5000                           # Flask tourne ?
iptables -I INPUT -p tcp --dport 5000 -j ACCEPT  # ouvrir le port
python3 /root/dashboard.py                     # relancer
```

### Aucune alerte dans le dashboard

```bash
# Wazuh génère des alertes ?
wc -l /var/ossec/logs/alerts/alerts.json

# Pipeline tourne ?
ps aux | grep soc_ai.py
tail -f /root/soc_ai.log

# Réinitialiser le cache (force le retraitement de tout)
echo "[]" > /root/processed_cache.json
```

### Internet inaccessible depuis Wazuh (AbuseIPDB / VirusTotal KO)

```bash
ping 8.8.8.8            # si "Network is unreachable"

# Activer la carte NAT
ip link set eth1 up
dhclient eth1

# Rendre permanent
echo -e 'DEVICE=eth1\nBOOTPROTO=dhcp\nONBOOT=yes' \
  > /etc/sysconfig/network-scripts/ifcfg-eth1
systemctl restart network
```

### SSH pfSense demande un mot de passe

```bash
# Vérifier que la clé est bien chargée
ssh -v admin@192.168.56.254 "echo OK"

# Régénérer et recopier si nécessaire
ssh-keygen -t rsa -b 2048 -f /root/.ssh/id_rsa -N ""
cat /root/.ssh/id_rsa.pub
# → coller dans pfSense : System → User Manager → admin → Authorized SSH Keys
```

---

## 📝 Commandes utiles

```bash
# Voir les logs en temps réel
tail -f /root/soc_ai.log

# Vérifier les incidents actifs
cat /root/soc_db.json | python3 -m json.tool | head -80

# Remettre à zéro (repartir de zéro sans perdre les fichiers de config)
echo "[]" > /root/soc_db.json
echo "[]" > /root/soc_db_closed.json
echo "[]" > /root/processed_cache.json

# Status Wazuh
/var/ossec/bin/ossec-control status

# Tester le blocage pfSense manuellement
ssh admin@192.168.56.254 "pfctl -t blocklist -T show"
ssh admin@192.168.56.254 "pfctl -t blocklist -T add 1.2.3.4"
ssh admin@192.168.56.254 "pfctl -t blocklist -T delete 1.2.3.4"

# Voir les modèles Ollama disponibles
curl http://192.168.56.105:11434/api/tags | python3 -m json.tool
```

---

## 🛠️ Stack technologique

| Composant | Version | Rôle |
|---|---|---|
| Wazuh | 4.x | SIEM / XDR — collecte logs |
| Ollama | latest | Runtime LLM local |
| mranv/siem-llama-3.1 | — | Modèle LLM spécialisé SIEM |
| Python | 3.6 | Langage principal |
| Flask | 2.x | Serveur web dashboard |
| pfSense | 2.7+ | Pare-feu / blocage IP |
| AbuseIPDB | API v2 | Réputation IP |
| VirusTotal | API v3 | Analyse malware |
| Chart.js | 4.4.1 | Graphiques dashboard |
| VirtualBox | — | Hyperviseur lab |

---

<div align="center">
<sub>SOC AI — Wazuh · mranv/siem-llama-3.1 · pfSense · AbuseIPDB · VirusTotal</sub>
</div>
