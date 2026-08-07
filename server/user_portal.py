"""User self-service portal (Phase 2 section 5).

Flask app on port 8001:
  - login with the same SQLite credentials (secure cookie session)
  - session lifetime: 24h normal, 30 days with Remember Me
  - account view: status + total/used/remaining quota
  - simulated quota purchase: auto-approved and applied to the LIVE
    tunnel session without requiring a reconnect (doc 5.4)
"""
import time
from functools import wraps
from flask import (Flask, render_template_string, request,
                   redirect, url_for, session)

LOGIN = """
<!doctype html><html><head><title>User Login</title><style>
body{font-family:sans-serif;background:#101418;color:#eee;display:flex;
justify-content:center;align-items:center;height:100vh}
form{background:#1b222a;padding:2rem;border-radius:10px}input{padding:6px}
</style></head><body>
<form method="post"><h2>User Portal</h2>
<input name="username" placeholder="username"><br><br>
<input name="password" type="password" placeholder="password"><br><br>
<label><input type="checkbox" name="remember" value="1"> Remember me (30 days)</label><br><br>
<button>Login</button>{% if error %}<p style="color:#f66">{{ error }}</p>{% endif %}
</form></body></html>
"""

PAGE = """
<!doctype html><html><head><title>User Portal</title><style>
body{font-family:sans-serif;background:#101418;color:#eee;margin:2rem}
.card{background:#1b222a;padding:1.5rem;border-radius:10px;max-width:560px}
.ok{color:#6f6}.bad{color:#f66}button{padding:8px 16px}
</style></head><body>
<div class="card">
<h2>User Portal</h2><p><a href="/logout">Logout</a></p>
{% if msg %}<p class="ok">{{ msg }}</p>{% endif %}
<p>User: <b>{{ u.username }}</b></p>
<p>Status: {% if u.status == 'active' %}<span class="ok">Active</span>
{% else %}<span class="bad">{{ u.status }}</span>{% endif %}</p>
<p>Total quota: {{ u.quota_mb }} MB</p>
<p>Used: {{ u.used_mb }} MB</p>
<p>Remaining: {{ u.remaining_mb }} MB</p>
{% if u.status != 'active' or u.remaining_mb < 100 %}
<form method="post" action="/buy"><button>Buy +2GB (auto-approved)</button></form>
{% endif %}
</div></body></html>
"""


def create_app(db, refresh_live_quota):
    app = Flask(__name__)
    app.secret_key = "iut-vpn-user-portal-secret"

    @app.before_request
    def check_expiry():
        """Enforce 24h / 30d session lifetimes stored in the cookie."""
        if session.get("user") and time.time() > session.get("expires_at", 0):
            session.clear()
            return redirect(url_for("login"))

    def require_login(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not session.get("user"):
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapper

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            u = db.get_user(request.form.get("username", ""))
            if (u and u.get("role", "user") == "user"
                    and db.verify_password(u, request.form.get("password", ""))):
                session["user"] = u["username"]
                days = 30 if request.form.get("remember") else 1
                session["expires_at"] = time.time() + days * 86400
                return redirect(url_for("dashboard"))
            error = "invalid credentials"
        return render_template_string(LOGIN, error=error)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    @require_login
    def dashboard():
        u = db.get_user(session["user"])
        u["used_mb"] = round(u["used_bytes"] / 1048576, 2)
        u["quota_mb"] = round(u["quota_bytes"] / 1048576, 1)
        u["remaining_mb"] = round(max(0, u["quota_bytes"] - u["used_bytes"]) / 1048576, 1)
        return render_template_string(PAGE, u=u, msg=request.args.get("msg"))

    @app.route("/buy", methods=["POST"])
    @require_login
    def buy():
        username = session["user"]
        db.add_user_quota(username, 2 * 1024 ** 3)   
        refresh_live_quota(username)                  
        return redirect(url_for("dashboard", msg="purchase applied: +2GB"))

    return app