#!/usr/bin/env python3
import json
import os
from datetime import date, datetime, timezone
from decimal import Decimal
from functools import wraps
from pathlib import Path

import boto3
import pymysql
from flask import Flask, redirect, render_template_string, request, session, url_for


app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "scenario2-finance-portal-lab-key")

PORTAL_USERNAME = os.getenv("APP_USER", os.getenv("PORTAL_USERNAME", "finance_admin"))
PORTAL_PASSWORD = os.getenv("APP_PASSWORD", os.getenv("PORTAL_PASSWORD", "finance2026"))
AWS_REGION = os.getenv("AWS_REGION", "eu-north-1")
SECRET_NAME = os.getenv("DB_SECRET_NAME", "ScenarioChain/FinanceRdsReader")
AUTH_LOG = Path(os.getenv("AUTH_LOG", "/var/log/finance-portal/auth.json"))


def client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",")[0].strip() if forwarded else (request.remote_addr or "unknown")


def write_auth_event(username, outcome):
    event = {
        "integration": "finance_portal",
        "event_type": "authentication",
        "action": "login",
        "outcome": outcome,
        "username": username or "<empty>",
        "source_ip": client_ip(),
        "user_agent": request.headers.get("User-Agent", "unknown"),
        "path": request.path,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        AUTH_LOG.parent.mkdir(parents=True, exist_ok=True)
        with AUTH_LOG.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, separators=(",", ":")) + "\n")
    except OSError:
        app.logger.exception("Could not write finance portal authentication event")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def database_config():
    response = boto3.client("secretsmanager", region_name=AWS_REGION).get_secret_value(
        SecretId=SECRET_NAME
    )
    secret = json.loads(response["SecretString"])
    return {
        "host": secret.get("host") or os.getenv("DB_HOST"),
        "port": int(secret.get("port") or os.getenv("DB_PORT", "3306")),
        "user": secret.get("username") or os.getenv("DB_USER", "finance_reader"),
        "password": secret.get("password") or os.getenv("DB_PASSWORD"),
        "database": secret.get("dbname")
        or secret.get("database")
        or os.getenv("DB_NAME", "finance_lab"),
    }


def finance_records():
    config = database_config()
    connection = pymysql.connect(
        **config,
        connect_timeout=5,
        cursorclass=pymysql.cursors.DictCursor,
    )
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, department, report_month, revenue_eur, notes "
                "FROM finance_records ORDER BY id"
            )
            return cursor.fetchall()
    finally:
        connection.close()


def printable(value):
    if isinstance(value, (date, datetime)):
        return value.isoformat()[:7]
    return str(value)


LOGIN_HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Devoteam Finance | Sign in</title>
  <style>
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #1d293d; background: #f2f5f9; }
    .shell { min-height: 100vh; display: grid; grid-template-columns: 42% 58%; }
    .brand { padding: 58px; background: #102338; color: white; display: flex; flex-direction: column; justify-content: space-between; }
    .brand-name { font-size: 30px; line-height: 1.02; font-weight: 800; }
    .brand-copy { max-width: 470px; margin-top: 90px; }
    .brand-copy h1 { font-size: 45px; line-height: 1.12; margin: 0 0 18px; }
    .brand-copy p, .footer { color: #c5d0dc; line-height: 1.7; }
    .signin { display: flex; align-items: center; justify-content: center; padding: 40px; }
    .card { width: 100%; max-width: 440px; background: white; border: 1px solid #d9e1ea; border-radius: 16px; padding: 38px; box-shadow: 0 18px 45px rgba(16,35,56,.08); }
    .card h2 { margin: 0 0 8px; font-size: 28px; }
    .muted { color: #66758a; margin: 0 0 30px; }
    label { display: block; margin: 18px 0 7px; font-size: 13px; font-weight: 700; color: #425167; }
    input { width: 100%; height: 46px; padding: 0 13px; border: 1px solid #cad4e0; border-radius: 8px; font-size: 15px; outline: none; }
    input:focus { border-color: #147d75; box-shadow: 0 0 0 3px rgba(20,125,117,.12); }
    button { width: 100%; height: 47px; margin-top: 24px; border: 0; border-radius: 8px; background: #147d75; color: white; font-size: 15px; font-weight: 800; cursor: pointer; }
    .error { margin: 0 0 18px; padding: 12px 14px; border-radius: 8px; color: #a12622; background: #fff0ef; border: 1px solid #ffd0cd; }
    @media (max-width: 780px) { .shell { grid-template-columns: 1fr; } .brand { display: none; } }
  </style>
</head>
<body>
  <main class="shell">
    <section class="brand">
      <div class="brand-name">Devoteam<br>Finance</div>
      <div class="brand-copy">
        <h1>Finance Reporting Portal</h1>
        <p>Internal reporting workspace connected to the private finance database.</p>
      </div>
      <div class="footer">Authorized company personnel only</div>
    </section>
    <section class="signin">
      <form class="card" method="post" action="/login">
        <h2>Welcome back</h2>
        <p class="muted">Sign in to access internal financial reports.</p>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        <label for="username">Username</label>
        <input id="username" name="username" autocomplete="username" required>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>
        <button type="submit">Sign in</button>
      </form>
    </section>
  </main>
</body>
</html>
"""


DASHBOARD_HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Finance Reporting Portal</title>
  <style>
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #1d293d; background: #f2f5f9; }
    .sidebar { position: fixed; inset: 0 auto 0 0; width: 247px; padding: 30px 25px; background: #102338; color: white; }
    .logo { font-size: 21px; line-height: 1.05; font-weight: 800; margin-bottom: 16px; }
    .side-copy { color: #c6d0dc; font-size: 14px; line-height: 1.5; margin: 0 0 36px; }
    .nav-item { display: block; margin: 0 0 10px; padding: 11px 12px; color: #dbe3ec; text-decoration: none; background: #263a4f; border-radius: 10px; }
    .main { margin-left: 247px; padding: 33px 40px 55px; min-height: 100vh; }
    .top { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 42px; }
    h1 { margin: 0 0 12px; font-size: 30px; }
    .month { margin: 0; font-size: 16px; }
    .logout { color: #172033; text-decoration: none; font-weight: 700; border: 1px solid #d4dce6; border-radius: 10px; padding: 10px 14px; background: white; }
    .cards { display: grid; grid-template-columns: repeat(3, 1fr); gap: 18px; margin-bottom: 24px; }
    .card { min-height: 107px; padding: 22px; background: white; border: 1px solid #d7e0ea; border-radius: 14px; }
    .label { color: #62728a; font-size: 13px; font-weight: 800; letter-spacing: .02em; text-transform: uppercase; }
    .value { margin-top: 8px; color: #117c72; font-size: 31px; line-height: 1.05; font-weight: 800; }
    .panel { overflow: hidden; background: white; border: 1px solid #d7e0ea; border-radius: 14px; }
    .panel-head { padding: 19px 22px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #dfe6ee; }
    .panel-head h2 { margin: 0; font-size: 20px; }
    .badge { padding: 6px 11px; border-radius: 999px; color: #08776f; background: #cdf9ef; font-size: 12px; font-weight: 800; }
    table { width: 100%; border-collapse: collapse; }
    th { padding: 14px 18px; color: #4d5c72; background: #f7f9fb; font-size: 12px; text-align: left; }
    td { padding: 14px 18px; border-top: 1px solid #e3e9f0; font-size: 16px; }
    .notes { color: #9c3e00; font-weight: 700; }
    .error { margin-bottom: 20px; padding: 14px 16px; color: #a12622; background: #fff0ef; border: 1px solid #ffd0cd; border-radius: 10px; }
    @media (max-width: 900px) { .sidebar { position: static; width: 100%; } .main { margin: 0; padding: 25px 18px; } .cards { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <aside class="sidebar">
    <div class="logo">Devoteam<br>Finance</div>
    <p class="side-copy">Internal reporting workspace connected to the private finance database.</p>
    <nav>
      <a class="nav-item" href="#dashboard">Dashboard</a>
      <a class="nav-item" href="#reports">Monthly Reports</a>
      <a class="nav-item" href="#records">Department Records</a>
      <a class="nav-item" href="#notes">Confidential Notes</a>
    </nav>
  </aside>
  <main class="main" id="dashboard">
    <header class="top">
      <div>
        <h1>Finance Dashboard</h1>
        <p class="month">Reporting month: {{ reporting_month }}</p>
      </div>
      <a class="logout" href="/logout">Logout</a>
    </header>
    {% if error %}<div class="error">Database error: {{ error }}</div>{% endif %}
    <section class="cards" id="reports">
      <article class="card"><div class="label">Total Revenue</div><div class="value">EUR {{ '%.2f'|format(total_revenue) }}</div></article>
      <article class="card"><div class="label">Departments</div><div class="value">{{ department_count }}</div></article>
      <article class="card"><div class="label">Data Source</div><div class="value">RDS</div></article>
    </section>
    <section class="panel" id="records">
      <div class="panel-head"><h2>Department Finance Records</h2><span class="badge">Live database data</span></div>
      <table>
        <thead><tr><th>ID</th><th>Department</th><th>Month</th><th>Revenue EUR</th><th>Internal Notes</th></tr></thead>
        <tbody>
          {% for row in records %}
          <tr>
            <td>{{ row.id }}</td><td>{{ row.department }}</td><td>{{ row.month }}</td>
            <td>{{ '%.2f'|format(row.revenue|float) }}</td><td class="notes" id="notes">{{ row.notes }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </section>
  </main>
</body>
</html>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(LOGIN_HTML, error=None)

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if username == PORTAL_USERNAME and password == PORTAL_PASSWORD:
        write_auth_event(username, "success")
        session.clear()
        session["authenticated"] = True
        session["username"] = username
        return redirect(url_for("dashboard"))

    write_auth_event(username, "failure")
    return render_template_string(
        LOGIN_HTML, error="Invalid username or password"
    ), 401


@app.route("/")
@login_required
def dashboard():
    rows = []
    error = None
    try:
        rows = finance_records()
    except Exception as exc:
        app.logger.exception("Could not load finance records")
        error = str(exc)

    normalized = []
    for row in rows:
        normalized.append(
            {
                "id": row.get("id"),
                "department": row.get("department"),
                "month": printable(row.get("report_month", "")),
                "revenue": row.get("revenue_eur", Decimal("0")),
                "notes": row.get("notes", ""),
            }
        )

    total = sum((Decimal(str(row["revenue"])) for row in normalized), Decimal("0"))
    departments = len({row["department"] for row in normalized})
    reporting_month = normalized[0]["month"] if normalized else "Unavailable"
    return render_template_string(
        DASHBOARD_HTML,
        records=normalized,
        total_revenue=float(total),
        department_count=departments,
        reporting_month=reporting_month,
        error=error,
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=False)
