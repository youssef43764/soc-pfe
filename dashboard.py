"""
Dashboard Web SOC AI — Flask avec authentification
Roles :
  - admin     : acces complet + gestion utilisateurs + terminal
  - analyst   : acces dashboard uniquement (lecture + fermeture alertes)

Comptes par defaut (crees au 1er demarrage) :
  admin   / admin123
  analyst / analyst123
"""
import json, os, hashlib, secrets, subprocess
from collections import defaultdict
from datetime import datetime
from functools import wraps
from flask import (Flask, render_template, jsonify, request,
                   redirect, url_for, session, Response, stream_with_context)

app = Flask(__name__)

# ==============================
# SECRET KEY PERSISTANTE
# ==============================
_KEY_FILE = "/root/.soc_secret_key"
if os.path.exists(_KEY_FILE):
    with open(_KEY_FILE) as _f:
        app.secret_key = _f.read().strip()
else:
    _key = secrets.token_hex(32)
    with open(_KEY_FILE, "w") as _f:
        _f.write(_key)
    os.chmod(_KEY_FILE, 0o600)
    app.secret_key = _key

# ==============================
# CHEMINS
# ==============================
DB_PATH     = "/root/soc_db.json"
CLOSED_PATH = "/root/soc_db_closed.json"
USERS_FILE  = "/root/users.json"

# ==============================
# GESTION UTILISATEURS
# ==============================
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    if not os.path.exists(USERS_FILE):
        default_users = [
            {
                "username": "admin",
                "password": hash_password("admin123"),
                "role":     "admin",
                "name":     "Administrateur",
                "created":  str(datetime.now())
            },
            {
                "username": "analyst",
                "password": hash_password("analyst123"),
                "role":     "analyst",
                "name":     "SOC Analyste",
                "created":  str(datetime.now())
            }
        ]
        save_users(default_users)
        return default_users
    try:
        with open(USERS_FILE) as f:
            return json.load(f)
    except:
        return []

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)

def get_user(username):
    return next((u for u in load_users() if u["username"] == username), None)

# ==============================
# DECORATEURS AUTH
# ==============================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            return render_template("unauthorized.html"), 403
        return f(*args, **kwargs)
    return decorated

# ==============================
# HELPERS DB
# ==============================
def load_db():
    if not os.path.exists(DB_PATH): return []
    try:
        with open(DB_PATH) as f: return json.load(f)
    except: return []

def save_db(data):
    with open(DB_PATH, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def load_closed():
    if not os.path.exists(CLOSED_PATH): return []
    try:
        with open(CLOSED_PATH) as f: return json.load(f)
    except: return []

def save_closed(data):
    with open(CLOSED_PATH, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def build_ip_stats(incidents):
    ip_data = defaultdict(lambda: {
        "total": 0, "p1": 0, "p2": 0, "p3": 0, "p4": 0,
        "blocked": False, "country": "—", "isp": "—",
        "max_score": 0, "last_update": ""
    })
    for i in incidents:
        ip = i.get("ip", "")
        if not ip: continue
        d = ip_data[ip]
        d["total"] += 1
        p = i.get("priority", "P4")
        if p == "P1":   d["p1"] += 1
        elif p == "P2": d["p2"] += 1
        elif p == "P3": d["p3"] += 1
        else:           d["p4"] += 1
        if i.get("blocked"): d["blocked"] = True
        if i.get("intel"):
            d["country"] = i["intel"].get("country", "—")
            d["isp"]     = i["intel"].get("isp", "—")
        score = i.get("score", 0)
        if score > d["max_score"]: d["max_score"] = score
        ts = i.get("timestamp") or i.get("last_update", "")
        if ts > d["last_update"]: d["last_update"] = ts
    return dict(ip_data)

def danger_score(stats):
    return (stats["p1"] * 30 + stats["p2"] * 15 +
            stats["p3"] * 5  + stats["p4"] * 1 +
            stats["max_score"])

# ==============================
# ROUTE LANDING PAGE
# ==============================
@app.route("/")
def landing():
    if "username" in session:
        return redirect(url_for("index"))
    return render_template("landing.html")

# ==============================
# ROUTES AUTH
# ==============================
@app.route("/login", methods=["GET", "POST"])
def login():
    if "username" in session:
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_user(username)
        if not user:
            error = "Identifiant introuvable"
        elif user["password"] != hash_password(password):
            error = "Mot de passe incorrect"
        else:
            session.permanent = True
            session["username"] = user["username"]
            session["role"]     = user["role"]
            session["name"]     = user["name"]
            return redirect(url_for("index"))
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))

# ==============================
# ROUTES ADMIN — GESTION UTILISATEURS
# ==============================
@app.route("/admin/users")
@admin_required
def admin_users():
    users = load_users()
    return render_template("admin_users.html", users=users, user=dict(session))

@app.route("/admin/users/create", methods=["POST"])
@admin_required
def admin_create_user():
    data     = request.get_json(force=True)
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role     = data.get("role", "analyst")
    name     = data.get("name", "").strip()
    if not username or not password or not name:
        return jsonify({"error": "Champs manquants"}), 400
    if role not in ("admin", "analyst"):
        return jsonify({"error": "Role invalide"}), 400
    users = load_users()
    if any(u["username"] == username for u in users):
        return jsonify({"error": "Utilisateur deja existant"}), 409
    users.append({
        "username": username,
        "password": hash_password(password),
        "role":     role,
        "name":     name,
        "created":  str(datetime.now())
    })
    save_users(users)
    return jsonify({"ok": True})

@app.route("/admin/users/update", methods=["POST"])
@admin_required
def admin_update_user():
    data     = request.get_json(force=True)
    username = data.get("username", "")
    users    = load_users()
    target   = next((u for u in users if u["username"] == username), None)
    if not target:
        return jsonify({"error": "Utilisateur introuvable"}), 404
    if data.get("name"):     target["name"] = data["name"]
    if data.get("role"):     target["role"] = data["role"]
    if data.get("password"): target["password"] = hash_password(data["password"])
    save_users(users)
    return jsonify({"ok": True})

@app.route("/admin/users/delete", methods=["POST"])
@admin_required
def admin_delete_user():
    data     = request.get_json(force=True)
    username = data.get("username", "")
    if username == session.get("username"):
        return jsonify({"error": "Impossible de supprimer son propre compte"}), 400
    users     = load_users()
    remaining = [u for u in users if u["username"] != username]
    if len(remaining) == len(users):
        return jsonify({"error": "Utilisateur introuvable"}), 404
    save_users(remaining)
    return jsonify({"ok": True})

# ==============================
# ROUTES TERMINAL (admin uniquement)
# ==============================
@app.route("/terminal")
@admin_required
def terminal():
    return render_template("terminal.html", user=dict(session))

@app.route("/terminal/run", methods=["POST"])
@admin_required
def terminal_run():
    data = request.get_json(force=True)
    cmd  = data.get("cmd", "").strip()
    cwd  = data.get("cwd", "/root")

    if not cmd:
        return jsonify({"output": "", "returncode": 0, "cwd": cwd})

    # Gestion du cd — pas de streaming, retour JSON direct
    if cmd.startswith("cd ") or cmd == "cd":
        target = cmd[3:].strip() if cmd != "cd" else os.path.expanduser("~")
        if not os.path.isabs(target):
            target = os.path.normpath(os.path.join(cwd, target))
        else:
            target = os.path.normpath(target)
        if os.path.isdir(target):
            return jsonify({"output": "", "returncode": 0, "cwd": target})
        else:
            return jsonify({
                "output":     "cd: {}: Aucun fichier ou dossier de ce type".format(target),
                "returncode": 1,
                "cwd":        cwd
            })

    # Toutes les autres commandes → streaming SSE ligne par ligne
    def generate():
        try:
            proc = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # stderr fusionné dans stdout
                cwd=cwd
            )
            # Lire ligne par ligne en temps réel
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace")
                # Format SSE : "data: ...\n\n"
                yield "data: {}\n\n".format(decoded.rstrip("\n"))
            proc.stdout.close()
            proc.wait()
            # Signal de fin avec le code de retour
            yield "data: __EXIT__:{}\n\n".format(proc.returncode)
        except Exception as e:
            yield "data: Erreur : {}\n\n".format(str(e))
            yield "data: __EXIT__:1\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no"
        }
    )

# ==============================
# ROUTES DASHBOARD
# ==============================
@app.route("/dashboard")
@login_required
def index():
    incidents   = load_db()
    closed      = load_closed()
    ip_stats    = build_ip_stats(incidents)
    top10       = sorted(ip_stats.items(), key=lambda x: danger_score(x[1]), reverse=True)[:10]
    global_stats = {
        "total_alerts": len(incidents),
        "total_ips":    len(ip_stats),
        "blocked_ips":  sum(1 for s in ip_stats.values() if s["blocked"]),
        "p1":    sum(1 for i in incidents if i.get("priority") == "P1"),
        "p2":    sum(1 for i in incidents if i.get("priority") == "P2"),
        "p3":    sum(1 for i in incidents if i.get("priority") == "P3"),
        "p4":    sum(1 for i in incidents if i.get("priority") == "P4"),
        "closed": len(closed),
    }
    sidebar_ips = sorted(ip_stats.items(), key=lambda x: danger_score(x[1]), reverse=True)
    return render_template("index.html",
        global_stats=global_stats,
        top10=top10,
        sidebar_ips=sidebar_ips,
        ip_stats=ip_stats,
        selected_ip=None,
        ip_alerts=[],
        user=dict(session))

@app.route("/ip/<path:ip>")
@login_required
def ip_view(ip):
    incidents    = load_db()
    closed       = load_closed()
    ip_stats     = build_ip_stats(incidents)
    ip_alerts    = sorted(
        [i for i in incidents if i.get("ip") == ip],
        key=lambda x: x.get("timestamp", ""), reverse=True)
    this_ip_stat = ip_stats.get(ip, {
        "total": 0, "p1": 0, "p2": 0, "p3": 0, "p4": 0,
        "blocked": False, "country": "—", "isp": "—",
        "max_score": 0, "last_update": ""
    })
    global_stats = {
        "total_alerts": len(incidents),
        "total_ips":    len(ip_stats),
        "blocked_ips":  sum(1 for s in ip_stats.values() if s["blocked"]),
        "p1":    sum(1 for i in incidents if i.get("priority") == "P1"),
        "p2":    sum(1 for i in incidents if i.get("priority") == "P2"),
        "p3":    sum(1 for i in incidents if i.get("priority") == "P3"),
        "p4":    sum(1 for i in incidents if i.get("priority") == "P4"),
        "closed": len(closed),
    }
    sidebar_ips = sorted(ip_stats.items(), key=lambda x: danger_score(x[1]), reverse=True)
    return render_template("index.html",
        global_stats=global_stats,
        top10=[],
        sidebar_ips=sidebar_ips,
        ip_stats=ip_stats,
        selected_ip=ip,
        selected_ip_stat=this_ip_stat,
        ip_alerts=ip_alerts,
        user=dict(session))

@app.route("/closed")
@login_required
def closed_page():
    incidents = sorted(load_closed(), key=lambda x: x.get("closed_at", ""), reverse=True)
    return render_template("closed.html", incidents=incidents, user=dict(session))

@app.route("/close/<alert_id>", methods=["POST"])
@login_required
def close_incident(alert_id):
    incidents = load_db()
    closed    = load_closed()
    target    = next((i for i in incidents if i.get("alert_id") == alert_id), None)
    if not target:
        return jsonify({"error": "Alerte introuvable"}), 404
    target["closed_at"] = str(datetime.now())
    target["closed_by"] = session.get("username", "unknown")
    target["status"]    = "closed"
    closed.append(target)
    save_closed(closed)
    save_db([i for i in incidents if i.get("alert_id") != alert_id])
    return jsonify({"ok": True})

@app.route("/reopen/<alert_id>", methods=["POST"])
@login_required
def reopen_incident(alert_id):
    closed    = load_closed()
    incidents = load_db()
    target    = next((i for i in closed if i.get("alert_id") == alert_id), None)
    if not target:
        return jsonify({"error": "Introuvable"}), 404
    target.pop("closed_at", None)
    target.pop("closed_by", None)
    target["status"] = "open"
    incidents.append(target)
    save_db(incidents)
    save_closed([i for i in closed if i.get("alert_id") != alert_id])
    return jsonify({"ok": True})

@app.route("/ask", methods=["POST"])
@login_required
def analyst_ask():
    data     = request.get_json(force=True)
    question = data.get("question", "")
    alert_id = data.get("alert_id", "")
    history  = data.get("history", [])
    if not question:
        return jsonify({"error": "question manquante"}), 400
    all_alerts = load_db() + load_closed()
    ctx = next((i for i in all_alerts if i.get("alert_id") == alert_id), {})
    try:
        from agents.assistant import ask
        response = ask(question, ctx, history)
    except Exception as e:
        response = "Assistant indisponible : {}".format(e)
    return jsonify({"response": response})

@app.route("/api/incidents")
@login_required
def api_incidents():
    return jsonify(load_db())

@app.route("/api/stats")
@login_required
def api_stats():
    incidents = load_db()
    ip_stats  = build_ip_stats(incidents)
    top10     = sorted(ip_stats.items(), key=lambda x: danger_score(x[1]), reverse=True)[:10]
    return jsonify({
        "total_alerts": len(incidents),
        "total_ips":    len(ip_stats),
        "top10": [{"ip": ip, "stats": s} for ip, s in top10]
    })

# ==============================
# ROUTE PROFIL
# ==============================
@app.route("/profile")
@login_required
def profile():
    user_data = get_user(session.get("username"))
    return render_template("profile.html", user=dict(session), profile=user_data)

@app.route("/profile/update", methods=["POST"])
@login_required
def profile_update():
    data         = request.get_json(force=True)
    new_name     = data.get("name", "").strip()
    new_password = data.get("password", "")
    old_password = data.get("old_password", "")
    if not new_name:
        return jsonify({"error": "Le nom ne peut pas etre vide"}), 400
    users    = load_users()
    username = session.get("username")
    target   = next((u for u in users if u["username"] == username), None)
    if not target:
        return jsonify({"error": "Utilisateur introuvable"}), 404
    if new_password:
        if not old_password:
            return jsonify({"error": "Ancien mot de passe requis"}), 400
        if target["password"] != hash_password(old_password):
            return jsonify({"error": "Ancien mot de passe incorrect"}), 401
        if len(new_password) < 6:
            return jsonify({"error": "Minimum 6 caracteres"}), 400
        target["password"] = hash_password(new_password)
    target["name"] = new_name
    save_users(users)
    session["name"] = new_name
    return jsonify({"ok": True})

# ==============================
# ROUTE STATUS SOC AI
# ==============================
@app.route("/api/soc-status")
@login_required
def soc_status():
    try:
        result = subprocess.Popen(
            "pgrep -f soc_ai.py",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        out, _ = result.communicate()
        running = len(out.strip()) > 0
    except:
        running = False

    # Dernières lignes du log
    try:
        result2 = subprocess.Popen(
            "tail -n 20 /root/soc_ai.log",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        log_out, _ = result2.communicate()
        last_logs = log_out.decode("utf-8", errors="replace")
    except:
        last_logs = ""

    return jsonify({
        "running": running,
        "last_logs": last_logs
    })

# ==============================
# route rapport
# ==============================
@app.route("/rapport")
@login_required
def generate_rapport():
    from datetime import datetime

    # Récupérer les filtres depuis l'URL
    date_debut = request.args.get("debut", "")
    date_fin   = request.args.get("fin", "")

    incidents = load_db()
    closed    = load_closed()
    all_inc   = incidents + closed

    # Filtrer par période
    filtered = []
    for i in all_inc:
        ts = (i.get("timestamp") or i.get("last_update", ""))[:19]
        if not ts:
            continue
        if date_debut and ts < date_debut:
            continue
        if date_fin and ts > date_fin:
            continue
        filtered.append(i)

    filtered = sorted(filtered, key=lambda x: x.get("score", 0), reverse=True)

    stats = {
        "total":   len(filtered),
        "p1":      sum(1 for i in filtered if i.get("priority") == "P1"),
        "p2":      sum(1 for i in filtered if i.get("priority") == "P2"),
        "p3":      sum(1 for i in filtered if i.get("priority") == "P3"),
        "p4":      sum(1 for i in filtered if i.get("priority") == "P4"),
        "blocked": sum(1 for i in filtered if i.get("blocked")),
        "closed":  sum(1 for i in filtered if i.get("status") == "closed"),
    }

    return render_template("rapport.html",
        stats=stats,
        incidents=filtered,
        date_debut=date_debut,
        date_fin=date_fin,
        generated_at=str(datetime.now())[:19])
# ==============================
# MAIN
# ==============================
if __name__ == "__main__":
    load_users()
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
