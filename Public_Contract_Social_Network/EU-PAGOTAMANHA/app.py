from __future__ import annotations

import csv
import io
import os
from datetime import datetime
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, Response, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import crypto_utils as crypto
import database as db

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.context_processor
def inject_user():
    user = None
    if session.get("user_id"):
        user = db.get_user(session["user_id"])
    return {"current_user": user}


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Precisas de iniciar sessão.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


@app.route("/")
def index():
    contracts = db.get_public_contracts()
    return render_template("index.html", contracts=contracts)


@app.route("/contracts")
def contracts_list():
    return render_template("contracts.html", contracts=db.get_all_contracts())


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not nome or not email or not password:
            flash("Preenche todos os campos obrigatórios.", "danger")
            return render_template("register.html")
        if password != confirm:
            flash("As passwords não coincidem.", "danger")
            return render_template("register.html")
        if len(password) < 8:
            flash("A password deve ter pelo menos 8 caracteres.", "danger")
            return render_template("register.html")
        if db.get_user_by_email(email):
            flash("Esse e-mail já está registado.", "danger")
            return render_template("register.html")

        private_pem, public_pem = crypto.generate_rsa_keypair()
        encrypted = crypto.encrypt_private_key(private_pem, password)
        key_data = {"public_key": public_pem, **encrypted}
        user_id = db.create_user(nome, email, generate_password_hash(password), key_data)
        session["user_id"] = user_id
        flash("Conta criada. Foi gerado um par de chaves RSA.", "success")
        return redirect(url_for("dashboard"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = db.get_user_by_email(email)
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Credenciais inválidas.", "danger")
            return render_template("login.html")
        session.clear()
        session["user_id"] = user["id"]
        flash("Sessão iniciada.", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Sessão terminada.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    contracts = db.get_user_contracts(session["user_id"])
    pending = [c for c in contracts if c["estado"] == "pendente"]
    signed = [c for c in contracts if c["estado"] in ("assinado", "sanado")]
    return render_template("dashboard.html", contracts=contracts, pending=pending, signed=signed)


@app.route("/contracts/create", methods=["GET", "POST"])
@login_required
def create_contract():
    users = db.list_users(exclude_id=session["user_id"])
    kind = request.args.get("type", "loan")
    if request.method == "POST":
        title = request.form.get("titulo", "").strip()
        text = request.form.get("texto_contrato", "").strip()
        receiver_id = int(request.form.get("id_aceitante") or 0)
        visibility = request.form.get("visibilidade", "publico")
        password = request.form.get("password", "")
        encrypt_mode = request.form.get("encrypt_mode", "none")
        reveal_at = (request.form.get("reveal_at") or "").replace("T", " ") or None
        cipher_name = request.form.get("cipher", "AES-256-CBC")
        hmac_name = request.form.get("hmac_algorithm", "HMAC-SHA256")

        if not title or not text or not receiver_id or not password:
            flash("Título, texto, aceitante e password são obrigatórios.", "danger")
            return render_template("create_contract.html", users=users, kind=kind)

        keys = db.get_user_keys(session["user_id"])
        try:
            private_pem = crypto.decrypt_private_key(
                keys["encrypted_private_key"], password, keys["private_key_salt"], keys["private_key_iv"]
            )
        except Exception:
            flash("Não foi possível decifrar a tua chave privada. Confirma a password.", "danger")
            return render_template("create_contract.html", users=users, kind=kind)

        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        contract_payload = {
            "id_proponente": session["user_id"],
            "id_aceitante": receiver_id,
            "texto_contrato": text,
            "data_criacao": created_at,
        }
        signature = crypto.sign_payload(private_pem, crypto.canonical_contract_payload(contract_payload))
        data = {
            "titulo": title,
            "texto_contrato": text,
            "id_proponente": session["user_id"],
            "id_aceitante": receiver_id,
            "estado": "pendente",
            "visibilidade": visibility,
            "data_criacao": created_at,
            "proponente_signature": signature,
            "proponente_signed_at": created_at,
        }
        if encrypt_mode == "timed":
            enc = crypto.encrypt_contract_text(text, password, cipher_name, hmac_name)
            data.update(enc)
            data["reveal_at"] = reveal_at or None
        contract_id = db.create_contract(data)
        flash("Contrato criado e assinado pelo proponente.", "success")
        return redirect(url_for("view_contract", contract_id=contract_id))
    return render_template("create_contract.html", users=users, kind=kind)


@app.route("/contracts/<int:contract_id>")
def view_contract(contract_id: int):
    contract = db.get_contract(contract_id)
    if not contract:
        flash("Contrato não encontrado.", "danger")
        return redirect(url_for("contracts_list"))
    signatures = db.get_contract_signatures(contract_id)
    verification = []
    for sig in signatures:
        ok = crypto.verify_signature(sig["public_key"], crypto.canonical_contract_payload(contract), sig["assinatura_digital"])
        verification.append({**sig, "valid": ok})
    return render_template("view_contract.html", contract=contract, signatures=verification)


@app.route("/contracts/<int:contract_id>/sign", methods=["GET", "POST"])
@login_required
def sign_contract_view(contract_id: int):
    contract = db.get_contract(contract_id)
    if not contract:
        flash("Contrato não encontrado.", "danger")
        return redirect(url_for("dashboard"))
    if session["user_id"] not in (contract["id_proponente"], contract["id_aceitante"]):
        flash("Não fazes parte deste contrato.", "danger")
        return redirect(url_for("view_contract", contract_id=contract_id))
    signatures = db.get_contract_signatures(contract_id)
    own = next((s for s in signatures if s["id_utilizador"] == session["user_id"]), None)
    if own and own["assinatura_digital"]:
        flash("Já assinaste este contrato.", "info")
        return redirect(url_for("view_contract", contract_id=contract_id))
    if request.method == "POST":
        password = request.form.get("password", "")
        keys = db.get_user_keys(session["user_id"])
        try:
            private_pem = crypto.decrypt_private_key(
                keys["encrypted_private_key"], password, keys["private_key_salt"], keys["private_key_iv"]
            )
        except Exception:
            flash("Password inválida para decifrar a chave privada.", "danger")
            return render_template("sign_contract.html", contract=contract)
        signature = crypto.sign_payload(private_pem, crypto.canonical_contract_payload(contract))
        db.save_signature(contract_id, session["user_id"], signature)
        flash("Contrato assinado digitalmente.", "success")
        return redirect(url_for("view_contract", contract_id=contract_id))
    return render_template("sign_contract.html", contract=contract)


@app.route("/contracts/<int:contract_id>/verify")
def verify_contract(contract_id: int):
    contract = db.get_contract(contract_id)
    if not contract:
        flash("Contrato não encontrado.", "danger")
        return redirect(url_for("contracts_list"))
    rows = []
    for sig in db.get_contract_signatures(contract_id):
        rows.append({**sig, "valid": crypto.verify_signature(sig["public_key"], crypto.canonical_contract_payload(contract), sig["assinatura_digital"])})
    return render_template("verify.html", contract=contract, signatures=rows)


@app.route("/verify", methods=["GET", "POST"])
def verify_manual():
    result = None
    if request.method == "POST":
        public_key = request.form.get("public_key", "")
        payload = request.form.get("payload", "")
        signature = request.form.get("signature", "")
        result = crypto.verify_signature(public_key, payload.encode("utf-8"), signature)
    return render_template("verify_manual.html", result=result)


@app.route("/users")
def users_list():
    return render_template("users.html", users=db.list_users())


@app.route("/users/<int:user_id>")
def profile(user_id: int):
    user = db.get_user(user_id)
    keys = db.get_user_keys(user_id)
    if not user:
        flash("Utilizador não encontrado.", "danger")
        return redirect(url_for("users_list"))
    contracts = db.get_user_contracts(user_id)
    return render_template("profile.html", user=user, keys=keys, contracts=contracts)


@app.route("/contracts/<int:contract_id>/settle", methods=["POST"])
@login_required
def settle_contract(contract_id: int):
    contract = db.get_contract(contract_id)
    if contract and session["user_id"] in (contract["id_proponente"], contract["id_aceitante"]):
        db.mark_sanado(contract_id)
        flash("Contrato marcado como sanado.", "success")
    return redirect(url_for("view_contract", contract_id=contract_id))


@app.route("/contracts/<int:contract_id>/export")
def export_contract(contract_id: int):
    contract = db.get_contract(contract_id)
    if not contract:
        flash("Contrato não encontrado.", "danger")
        return redirect(url_for("contracts_list"))
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["campo", "valor"])
    for key in ["id", "titulo", "texto_contrato", "id_proponente", "id_aceitante", "estado", "data_criacao"]:
        writer.writerow([key, contract.get(key)])
    writer.writerow([])
    writer.writerow(["assinante", "tipo", "assinatura", "public_key"])
    for s in db.get_contract_signatures(contract_id):
        writer.writerow([s["email"], s["tipo_assinante"], s["assinatura_digital"], s["public_key"]])
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename=contract_{contract_id}.csv"})


# aliases para templates antigos
home = index
contract_detail = view_contract


if __name__ == "__main__":
    db.init_db()
    app.run(host=os.getenv("BIND_HOST", "127.0.0.1"), port=int(os.getenv("BIND_PORT", "5000")), debug=True)
