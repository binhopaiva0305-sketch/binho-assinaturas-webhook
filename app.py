import os
import re
import time
import hmac
import secrets
from collections import deque
from flask import Flask, request, jsonify, render_template, session, redirect, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", secrets.token_hex(32))

WEBHOOK_TOKEN = os.environ.get("WEBHOOK_TOKEN", "TROQUE-ESTE-TOKEN")
PAGE_PASSWORD = os.environ.get("PAGE_PASSWORD", "TROQUE-ESTA-SENHA")

# Cadastre aqui os remetentes autorizados.
# Exemplo: {"no-reply@servico.com", "account@servico.com"}
ALLOWED_SENDERS = {
    x.strip().lower()
    for x in os.environ.get("ALLOWED_SENDERS", "").split(",")
    if x.strip()
}

# Bloqueia assuntos/conteúdos relacionados a alterações sensíveis.
BLOCKED_WORDS = [
    "alteração de senha", "alteracao de senha",
    "alterar senha", "alterar e-mail", "alterar email",
    "mudança de senha", "mudanca de senha",
    "mudança de e-mail", "mudanca de e-mail",
    "password changed", "password reset",
    "email changed", "e-mail changed",
    "account recovery", "recuperação de conta",
    "recuperacao de conta", "recovery code",
]

# Armazenamento temporário em memória: reinicia quando o serviço reinicia.
CODES = deque(maxlen=100)
CODE_TTL = int(os.environ.get("CODE_TTL_SECONDS", "600"))

def extract_code(text):
    # Por segurança, só aceita códigos numéricos isolados de 4 a 8 dígitos.
    matches = re.findall(r"(?<!\d)\d{4,8}(?!\d)", text or "")
    return matches[0] if matches else None

def authorized_sender(sender):
    if not ALLOWED_SENDERS:
        return False
    sender = (sender or "").lower().strip()
    return any(sender == allowed or sender.endswith(">" + allowed) for allowed in ALLOWED_SENDERS)

def is_blocked(text):
    normalized = (text or "").lower()
    return any(word in normalized for word in BLOCKED_WORDS)

def cleanup():
    now = time.time()
    while CODES and now - CODES[0]["timestamp"] > CODE_TTL:
        CODES.popleft()

@app.get("/")
def index():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    cleanup()
    return render_template("index.html", codes=list(reversed(CODES)))

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        if hmac.compare_digest(password, PAGE_PASSWORD):
            session["logged_in"] = True
            return redirect(url_for("index"))
        error = "Senha incorreta."
    return render_template("login.html", error=error)

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.post("/webhook")
def webhook():
    token = request.headers.get("X-Webhook-Token", "")
    if not hmac.compare_digest(token, WEBHOOK_TOKEN):
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    data = request.get_json(silent=True) or request.form.to_dict()
    sender = str(data.get("from", data.get("sender", "")))
    subject = str(data.get("subject", ""))
    body = str(data.get("textbody", data.get("text", data.get("body", ""))))
    full_text = f"{subject}\n{body}"

    # Segurança: nada entra se o remetente não estiver autorizado.
    if not authorized_sender(sender):
        return jsonify({"ok": True, "accepted": False, "reason": "sender_not_allowed"})

    # Segurança: mensagens sensíveis são descartadas.
    if is_blocked(full_text):
        return jsonify({"ok": True, "accepted": False, "reason": "blocked_message"})

    code = extract_code(full_text)
    if not code:
        return jsonify({"ok": True, "accepted": False, "reason": "no_code_found"})

    cleanup()
    CODES.append({
        "service": subject[:80] or "Código recebido",
        "code": code,
        "timestamp": time.time(),
    })
    return jsonify({"ok": True, "accepted": True})

@app.get("/api/codes")
def api_codes():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    cleanup()
    return jsonify([
        {"service": x["service"], "code": x["code"]}
        for x in reversed(CODES)
    ])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
