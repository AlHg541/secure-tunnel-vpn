"""Admin web panel (Phase 2 section 4 + section 6 firewall management).

Flask dashboard served on port 8000:
  - login with the admin account stored in SQLite
  - live tables: users (usage/quota), active sessions, traffic log
  - kick button to disconnect any client instantly
  - firewall rule management (add/delete drop-accept rules)
"""
import time
from functools import wraps
from flask import (Flask, render_template_string, request,
                   redirect, url_for, session)

LOGIN = """
<!doctype html><html><head><title>Admin Login</title><style>
body{font-family:sans-serif;background:#111;color:#eee;display:flex;justify-content:center;align-items:center;height:100vh}
form{background:#222;padding:2rem;border-radius:8px}input{padding:6px}
</style></head><body>
<form method=post><h2>VPN Admin Panel</h2>
<input name=username placeholder="username"><br><br>
<input name=password type=password placeholder="password"><br><br>
<button>Login</button>{% if error %}<p style="color:#f66">{{ error }}</p>{% endif %}
</form></body></html>
"""

PAGE = """
<!doctype html><html><head><title>VPN Admin</title><style>
body{font-family:sans-serif;background:#111;color:#eee;margin:2rem}
table{border-collapse:collapse;margin-bottom:2rem}
td,th{border:1px solid #444;padding:6px 10px}h3{color:#7cf}
input,select{padding:4px;margin:2px}
</style></head><body>
<h2>VPN Admin Panel</h2><p><a href="/logout">Logout</a></p>

<h3>Users</h3>
<table><tr><th>User</th><th>Status</th><th>Used (MB)</th><th>Quota (MB)</th><th>Rate (KB/s)</th><th>Role</th></tr>
{% for u in users %}<tr><td>{{ u.username }}</td><td>{{ u.status }}</td>
<td>{{ (u.used_bytes/1048576)|round(2) }}</td><td>{{ (u.quota_bytes/1048576)|round(1) }}</td>
<td>{{ u.rate_limit_bps//1024 }}</td><td>{{ u.role }}</td></tr>{% endfor %}</table>

<h3>Active Sessions</h3>
<table><tr><th>User</th><th>Inner IP</th><th>Up (KB)</th><th>Down (KB)</th><th>Action</th></tr>
{% for s in sessions %}<tr><td>{{ s.username }}</td><td>{{ s.inner_ip }}</td>
<td>{{ (s.up/1024)|round(1) }}</td><td>{{ (s.down/1024)|round(1) }}</td>
<td><form method=post action="/kick" style="display:inline">
<input type=hidden name=inner_ip value="{{ s.inner_ip }}"><button>Kick</button></form></td></tr>
{% else %}<tr><td colspan=5>no active sessions</td></tr>{% endfor %}</table>

<h3>Traffic Log (latest 50)</h3>
<table><tr><th>Time</th><th>User</th><th>Destination</th><th>Port</th><th>App</th><th>Domain</th></tr>
{% for t in traffic %}<tr><td>{{ t.ts }}</td><td>{{ t.username }}</td><td>{{ t.dst_ip }}</td>
<td>{{ t.dst_port }}</td><td>{{ t.app_protocol }}</td><td>{{ t.domain or '' }}</td></tr>{% endfor %}</table>

<h3>Firewall Rules</h3>
<form method="post" action="/firewall/add">
<select name="action"><option value="drop">DROP</option><option value="accept">ACCEPT</option></select>
<input name="dst_ip" placeholder="dst IP (optional)">
<input name="dst_port" placeholder="dst port (optional)">
<input name="domain" placeholder="domain (optional)">
<select name="scope"><option value="global">global</option><option value="client">per-client</option></select>
<input name="username" placeholder="username (per-client)">
<button>Add rule</button></form>
<table><tr><th>ID</th><th>Action</th><th>IP</th><th>Port</th><th>Domain</th><th>Scope</th><th>User</th><th></th></tr>
{% for r in rules %}<tr><td>{{ r.id }}</td><td>{{ r.action }}</td><td>{{ r.dst_ip or '' }}</td>
<td>{{ r.dst_port or '' }}</td><td>{{ r.domain or '' }}</td><td>{{ r.scope }}</td><td>{{ r.username or '' }}</td>
<td><form method="post" action="/firewall/del" style="display:inline">
<input type=hidden name="id" value="{{ r.id }}"><button>Delete</button></form></td></tr>
{% else %}<tr><td colspan=8>no rules (default allow)</td></tr>{% endfor %}</table>
</body></html>
"""


def create_app(db, get_active_sessions, kick_client):
    app = Flask(__name__)
    app.secret_key = "iut-vpn-admin-secret-change-me"

    def require_login(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not session.get("admin"):
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapper

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            user = db.get_user(request.form.get("username", ""))
            if (user and user.get("role") == "admin"
                    and db.verify_password(user, request.form.get("password", ""))):
                session["admin"] = user["username"]
                return redirect(url_for("dashboard"))
            error = "invalid admin credentials"
        return render_template_string(LOGIN, error=error)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    @require_login
    def dashboard():
        traffic = db.get_traffic_log(50)
        for row in traffic:
            row["ts"] = time.strftime("%m-%d %H:%M:%S",
                                      time.localtime(row["timestamp"]))
        return render_template_string(PAGE, users=db.get_all_users(),
                                      sessions=get_active_sessions(),
                                      traffic=traffic,
                                      rules=db.get_firewall_rules())

    @app.route("/kick", methods=["POST"])
    @require_login
    def kick():
        kick_client(request.form.get("inner_ip"))
        return redirect(url_for("dashboard"))

    @app.route("/firewall/add", methods=["POST"])
    @require_login
    def fw_add():
        f = request.form
        db.add_firewall_rule(f.get("action"), f.get("dst_ip"), f.get("dst_port"),
                             f.get("domain"), f.get("scope"), f.get("username"))
        return redirect(url_for("dashboard"))

    @app.route("/firewall/del", methods=["POST"])
    @require_login
    def fw_del():
        db.delete_firewall_rule(int(request.form.get("id")))
        return redirect(url_for("dashboard"))

    return app