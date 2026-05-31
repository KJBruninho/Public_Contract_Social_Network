from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import os
import secrets
import struct
import time
import zipfile
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import quote, urlencode

from dotenv import load_dotenv
from flask import Flask, Response, flash, redirect, render_template, request, session, url_for
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

import crypto_utils as crypto
import database as db

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

MFA_ISSUER = "EU-PAGOTAMANHA"
MFA_INTERVAL_SECONDS = 30
MFA_DIGITS = 6
LOGIN_BLOCK_THRESHOLD = int(os.getenv("LOGIN_BLOCK_THRESHOLD", "5"))
LOGIN_BLOCK_WINDOW_MINUTES = int(os.getenv("LOGIN_BLOCK_WINDOW_MINUTES", "5"))
PASSWORD_MAX_AGE_DAYS = int(os.getenv("PASSWORD_MAX_AGE_DAYS", "30"))


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


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def csrf_field() -> Markup:
    return Markup(f'<input type="hidden" name="csrf_token" value="{csrf_token()}">')


@app.before_request
def validate_csrf():
    if request.method != "POST":
        return None
    expected = session.get("csrf_token")
    supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        audit("CSRF_FAIL", success=False, details=request.path)
        return Response("CSRF token inválido.", status=400)
    return None


@app.context_processor
def inject_globals():
    user = None
    if session.get("user_id"):
        user = db.get_user(session["user_id"])
    return {"current_user": user, "csrf_token": csrf_token, "csrf_field": csrf_field}


def client_ip() -> str | None:
    forwarded = request.headers.get("X-Forwarded-For", "")
    return (forwarded.split(",")[0].strip() if forwarded else request.remote_addr) or None


def audit(action: str, *, contract_id: int | None = None, details: str | None = None, success: bool = True, user_id: int | None = None, email: str | None = None) -> None:
    try:
        db.add_audit_log(
            action=action,
            user_id=user_id if user_id is not None else session.get("user_id"),
            email=email,
            contract_id=contract_id,
            success=success,
            details=details,
            ip_address=client_ip(),
            user_agent=request.headers.get("User-Agent", ""),
        )
    except Exception:
        # Audit must never break the user action.
        pass


def password_expired(user: dict | None) -> bool:
    if not user:
        return False
    if user.get("must_change_password"):
        return True
    changed = user.get("password_changed_at") or user.get("data_registo")
    if not changed:
        return False
    if isinstance(changed, str):
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                changed = datetime.strptime(changed, fmt)
                break
            except ValueError:
                pass
    return isinstance(changed, datetime) and datetime.now() - changed > timedelta(days=PASSWORD_MAX_AGE_DAYS)


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Precisas de iniciar sessão.", "warning")
            return redirect(url_for("login"))
        if request.endpoint not in {"change_password", "logout"}:
            user = db.get_user(session["user_id"])
            if password_expired(user):
                flash("A tua password expirou. Atualiza-a para continuar.", "warning")
                return redirect(url_for("change_password"))
        return fn(*args, **kwargs)
    return wrapper


def _current_user_id() -> int | None:
    user_id = session.get("user_id")
    return int(user_id) if user_id else None


def _is_contract_party(contract: dict, user_id: int | None) -> bool:
    return bool(user_id and user_id in (contract.get("id_proponente"), contract.get("id_aceitante")))


def can_view_contract(contract: dict) -> bool:
    viewer_id = _current_user_id()
    is_public_published = contract.get("visibilidade") == "publico" and contract.get("estado") in ("assinado", "sanado")
    return is_public_published or _is_contract_party(contract, viewer_id)


def deny_if_cannot_view(contract: dict):
    if can_view_contract(contract):
        return None
    flash("Não tens permissão para ver este contrato.", "danger")
    return redirect(url_for("contracts_list"))


def _parse_datetime(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(str(value), fmt)
        except ValueError:
            pass
    return None


def _format_datetime(value: datetime | None) -> str | None:
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else None


def public_reveal_time_reached(contract: dict) -> bool:
    if not contract.get("encrypted_text"):
        return True
    reveal_at = _parse_datetime(contract.get("reveal_at"))
    return bool(reveal_at and datetime.now() >= reveal_at)


def can_read_plaintext(contract: dict) -> bool:
    if not contract.get("encrypted_text"):
        return True
    return public_reveal_time_reached(contract) or _is_contract_party(contract, _current_user_id())


def contract_for_display(contract: dict) -> dict:
    visible = dict(contract)
    visible["plain_text_visible"] = can_read_plaintext(contract)
    visible["public_reveal_reached"] = public_reveal_time_reached(contract)
    if contract.get("encrypted_text") and not visible["plain_text_visible"]:
        reveal_at = contract.get("reveal_at") or "data não definida"
        visible["texto_contrato"] = f"[Texto cifrado até {reveal_at}]"
    return visible


def contracts_for_display(contracts: list[dict]) -> list[dict]:
    return [contract_for_display(contract) for contract in contracts]


def generate_mfa_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _decode_mfa_secret(secret: str) -> bytes:
    compact = "".join(str(secret).upper().split())
    compact += "=" * ((8 - len(compact) % 8) % 8)
    return base64.b32decode(compact, casefold=True)


def generate_totp(secret: str, for_time: int | None = None) -> str:
    counter = int((for_time or int(time.time())) // MFA_INTERVAL_SECONDS)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(_decode_mfa_secret(secret), msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** MFA_DIGITS)).zfill(MFA_DIGITS)


def verify_totp(secret: str | None, code: str, window: int = 1) -> bool:
    if not secret:
        return False
    clean = "".join(ch for ch in str(code) if ch.isdigit())
    if len(clean) != MFA_DIGITS:
        return False
    now = int(time.time())
    for step in range(-window, window + 1):
        if hmac.compare_digest(generate_totp(secret, now + step * MFA_INTERVAL_SECONDS), clean):
            return True
    return False


def mfa_otpauth_uri(user: dict, secret: str) -> str:
    label = f"{MFA_ISSUER}:{user['email']}"
    params = urlencode({"secret": secret, "issuer": MFA_ISSUER, "algorithm": "SHA1", "digits": str(MFA_DIGITS), "period": str(MFA_INTERVAL_SECONDS)})
    return f"otpauth://totp/{quote(label)}?{params}"


def qr_data_uri(data: str) -> str | None:
    try:
        import qrcode
    except Exception:
        return None
    buffer = io.BytesIO()
    img = qrcode.make(data)
    img.save(buffer, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")


@app.route("/")
def index():
    return render_template("index.html", contracts=contracts_for_display(db.get_public_contracts()))


@app.route("/contracts")
def contracts_list():
    return render_template("contracts.html", contracts=contracts_for_display(db.get_visible_contracts(_current_user_id())))


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
        user_id = db.create_user(nome, email, generate_password_hash(password, method="scrypt", salt_length=16), key_data)
        session.clear()
        csrf_token()
        session["user_id"] = user_id
        audit("REGISTER_OK", user_id=user_id, email=email)
        flash("Conta criada. Foi gerado um par de chaves RSA.", "success")
        return redirect(url_for("dashboard"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if db.count_recent_failed_logins(email, client_ip(), LOGIN_BLOCK_WINDOW_MINUTES) >= LOGIN_BLOCK_THRESHOLD:
            audit("LOGIN_BLOCKED", email=email, success=False)
            flash(f"Demasiadas tentativas falhadas. Tenta novamente dentro de {LOGIN_BLOCK_WINDOW_MINUTES} minutos.", "danger")
            return render_template("login.html")
        user = db.get_user_by_email(email)
        if not user or not check_password_hash(user["password_hash"], password):
            audit("LOGIN_FAIL", email=email, success=False)
            flash("Credenciais inválidas.", "danger")
            return render_template("login.html")

        session.clear()
        csrf_token()
        if user.get("mfa_enabled"):
            session["pending_mfa_user_id"] = user["id"]
            audit("LOGIN_PASSWORD_OK_MFA_REQUIRED", user_id=user["id"], email=email)
            flash("Introduz o código MFA para concluir o login.", "info")
            return redirect(url_for("mfa_verify"))

        session["user_id"] = user["id"]
        audit("LOGIN_OK", user_id=user["id"], email=email)
        flash("Sessão iniciada.", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/mfa/verify", methods=["GET", "POST"])
def mfa_verify():
    pending_user_id = session.get("pending_mfa_user_id")
    if not pending_user_id:
        flash("Inicia sessão primeiro.", "warning")
        return redirect(url_for("login"))
    user = db.get_user(int(pending_user_id))
    if not user or not user.get("mfa_enabled"):
        session.clear()
        flash("O desafio MFA já não é válido.", "warning")
        return redirect(url_for("login"))
    if request.method == "POST":
        code = request.form.get("code", "")
        if verify_totp(user.get("mfa_secret"), code):
            session.clear()
            csrf_token()
            session["user_id"] = user["id"]
            audit("LOGIN_OK", user_id=user["id"], email=user["email"])
            flash("Sessão iniciada com MFA.", "success")
            return redirect(url_for("dashboard"))
        audit("MFA_LOGIN_FAIL", user_id=user["id"], email=user["email"], success=False)
        flash("Código MFA inválido ou expirado.", "danger")
    return render_template("mfa_verify.html", user=user)


@app.route("/mfa/setup", methods=["GET", "POST"])
@login_required
def mfa_setup():
    user = db.get_user(session["user_id"])
    if not user:
        session.clear()
        flash("Sessão inválida.", "danger")
        return redirect(url_for("login"))
    if request.method == "POST":
        action = request.form.get("action", "enable")
        password = request.form.get("password", "")
        code = request.form.get("code", "")
        if not check_password_hash(user["password_hash"], password):
            audit("MFA_PASSWORD_FAIL", success=False)
            flash("Password inválida.", "danger")
            return redirect(url_for("mfa_setup"))
        if action == "disable":
            if not user.get("mfa_enabled") or not verify_totp(user.get("mfa_secret"), code):
                audit("MFA_DISABLE_FAIL", success=False)
                flash("Código MFA inválido.", "danger")
                return redirect(url_for("mfa_setup"))
            db.set_mfa(user["id"], enabled=False, secret=None)
            audit("MFA_DISABLED")
            flash("MFA desativado.", "success")
            return redirect(url_for("security_dashboard"))
        setup_secret = user.get("mfa_secret") or generate_mfa_secret()
        if not user.get("mfa_secret"):
            db.set_mfa(user["id"], enabled=False, secret=setup_secret)
        if not verify_totp(setup_secret, code):
            audit("MFA_ENABLE_FAIL", success=False)
            flash("Código MFA inválido. Confirma o QR code e tenta novamente.", "danger")
            return redirect(url_for("mfa_setup"))
        db.set_mfa(user["id"], enabled=True, secret=setup_secret)
        audit("MFA_ENABLED")
        flash("MFA ativado com sucesso.", "success")
        return redirect(url_for("security_dashboard"))
    if user.get("mfa_enabled"):
        return render_template("mfa_setup.html", user=user, enabled=True, secret=None, qr_uri=None, qr_image=None)
    secret = user.get("mfa_secret") or generate_mfa_secret()
    if not user.get("mfa_secret"):
        db.set_mfa(user["id"], enabled=False, secret=secret)
    uri = mfa_otpauth_uri(user, secret)
    return render_template("mfa_setup.html", user=user, enabled=False, secret=secret, qr_uri=uri, qr_image=qr_data_uri(uri))


@app.route("/logout")
def logout():
    audit("LOGOUT")
    session.clear()
    flash("Sessão terminada.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    raw_contracts = db.get_user_contracts(session["user_id"])
    pending = [c for c in raw_contracts if c["estado"] == "pendente"]
    signed = [c for c in raw_contracts if c["estado"] in ("assinado", "sanado")]
    contracts = contracts_for_display(raw_contracts)
    return render_template("dashboard.html", contracts=contracts, pending=pending, signed=signed)


@app.route("/security")
@login_required
def security_dashboard():
    user = db.get_user(session["user_id"])
    logs = db.get_user_audit_logs(session["user_id"], limit=50)
    stats = db.get_security_stats(session["user_id"])
    return render_template("security.html", user=user, logs=logs, stats=stats, password_expired=password_expired(user), password_max_age=PASSWORD_MAX_AGE_DAYS)


@app.route("/security/password", methods=["GET", "POST"])
@login_required
def change_password():
    user = db.get_user(session["user_id"])
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if not check_password_hash(user["password_hash"], current):
            audit("PASSWORD_CHANGE_FAIL", success=False, details="bad current password")
            flash("Password atual inválida.", "danger")
            return render_template("change_password.html", user=user)
        if len(new) < 8 or new != confirm:
            flash("A nova password tem de ter pelo menos 8 caracteres e coincidir com a confirmação.", "danger")
            return render_template("change_password.html", user=user)
        for item in db.get_password_history(user["id"], limit=3):
            if check_password_hash(item["password_hash"], new):
                flash("Não podes reutilizar uma das últimas 3 passwords.", "danger")
                return render_template("change_password.html", user=user)
        keys = db.get_user_keys(user["id"])
        try:
            private_pem = crypto.decrypt_private_key(keys["encrypted_private_key"], current, keys["private_key_salt"], keys["private_key_iv"])
        except Exception:
            audit("PASSWORD_CHANGE_FAIL", success=False, details="private key decrypt failed")
            flash("Não foi possível decifrar a chave privada com a password atual.", "danger")
            return render_template("change_password.html", user=user)
        key_data = crypto.encrypt_private_key(private_pem, new)
        db.update_user_password_and_keys(user["id"], generate_password_hash(new, method="scrypt", salt_length=16), key_data)
        audit("PASSWORD_CHANGED")
        flash("Password atualizada e chave privada recifrada.", "success")
        return redirect(url_for("security_dashboard"))
    return render_template("change_password.html", user=user)


@app.route("/contracts/create", methods=["GET", "POST"])
@login_required
def create_contract():
    users = db.list_users(exclude_id=session["user_id"])
    kind = request.args.get("type", "loan")
    if request.method == "POST":
        title = request.form.get("titulo", "").strip()
        text = request.form.get("texto_contrato", "").strip()
        try:
            receiver_id = int(request.form.get("id_aceitante") or 0)
        except ValueError:
            receiver_id = 0
        visibility = request.form.get("visibilidade", "publico")
        password = request.form.get("password", "")
        encrypt_mode = request.form.get("encrypt_mode", "none")
        reveal_raw = (request.form.get("reveal_at") or "").strip()
        reveal_at_dt = _parse_datetime(reveal_raw.replace("T", " ")) if reveal_raw else None
        encryption_profile = request.form.get("encryption_profile", "none")
        if not title or not text or not receiver_id or not password:
            flash("Título, texto, aceitante e password são obrigatórios.", "danger")
            return render_template("create_contract.html", users=users, kind=kind)
        if receiver_id == session["user_id"] or not db.get_user(receiver_id):
            flash("Seleciona um aceitante válido.", "danger")
            return render_template("create_contract.html", users=users, kind=kind)
        if visibility not in ("publico", "privado"):
            visibility = "publico"
        if encrypt_mode == "timed":
            if not reveal_at_dt:
                flash("Define a data de revelação do contrato cifrado.", "danger")
                return render_template("create_contract.html", users=users, kind=kind)
            if reveal_at_dt <= datetime.now():
                flash("A data de revelação tem de ser futura.", "danger")
                return render_template("create_contract.html", users=users, kind=kind)
        keys = db.get_user_keys(session["user_id"])
        try:
            private_pem = crypto.decrypt_private_key(keys["encrypted_private_key"], password, keys["private_key_salt"], keys["private_key_iv"])
        except Exception:
            audit("CONTRACT_CREATE_FAIL", success=False, details="private key decrypt failed")
            flash("Não foi possível decifrar a tua chave privada. Confirma a password.", "danger")
            return render_template("create_contract.html", users=users, kind=kind)
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        contract_payload = {"id_proponente": session["user_id"], "id_aceitante": receiver_id, "texto_contrato": text, "data_criacao": created_at}
        signature = crypto.sign_payload(private_pem, crypto.canonical_contract_payload(contract_payload))
        data = {"titulo": title, "texto_contrato": text, "id_proponente": session["user_id"], "id_aceitante": receiver_id, "estado": "pendente", "visibilidade": visibility, "data_criacao": created_at, "proponente_signature": signature, "proponente_signed_at": created_at}
        if encrypt_mode == "timed":
            try:
                selected_combo = crypto.parse_encryption_profile(encryption_profile)
                if selected_combo is None:
                    flash("Seleciona uma combinação de cifra e HMAC.", "danger")
                    return render_template("create_contract.html", users=users, kind=kind)
                cipher_name, hmac_name = selected_combo
                data.update(crypto.encrypt_contract_text(text, password, cipher_name, hmac_name))
            except ValueError:
                flash("Combinação de cifra/HMAC inválida.", "danger")
                return render_template("create_contract.html", users=users, kind=kind)
            data["reveal_at"] = _format_datetime(reveal_at_dt)
        contract_id = db.create_contract(data)
        audit("CONTRACT_CREATED", contract_id=contract_id)
        flash("Contrato criado e assinado pelo proponente.", "success")
        return redirect(url_for("view_contract", contract_id=contract_id))
    return render_template("create_contract.html", users=users, kind=kind)


@app.route("/contracts/<int:contract_id>")
def view_contract(contract_id: int):
    raw_contract = db.get_contract(contract_id)
    if not raw_contract:
        flash("Contrato não encontrado.", "danger")
        return redirect(url_for("contracts_list"))
    denied = deny_if_cannot_view(raw_contract)
    if denied:
        return denied
    contract = contract_for_display(raw_contract)
    signatures = []
    for sig in db.get_contract_signatures(contract_id):
        ok = crypto.verify_signature(sig["public_key"], crypto.canonical_contract_payload(raw_contract), sig["assinatura_digital"])
        signatures.append({**sig, "valid": ok})
    audit("CONTRACT_VIEWED", contract_id=contract_id)
    contract_url = url_for("view_contract", contract_id=contract_id, _external=True)
    return render_template("view_contract.html", contract=contract, raw_contract=raw_contract, signatures=signatures, contract_qr_image=qr_data_uri(contract_url), contract_url=contract_url)


@app.route("/contracts/<int:contract_id>/sign", methods=["GET", "POST"])
@login_required
def sign_contract_view(contract_id: int):
    contract = db.get_contract(contract_id)
    if not contract:
        flash("Contrato não encontrado.", "danger")
        return redirect(url_for("dashboard"))
    if not _is_contract_party(contract, session["user_id"]):
        flash("Não fazes parte deste contrato.", "danger")
        return redirect(url_for("contracts_list"))
    if contract["estado"] != "pendente":
        flash("Este contrato já não está pendente e não pode ser assinado.", "warning")
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
            private_pem = crypto.decrypt_private_key(keys["encrypted_private_key"], password, keys["private_key_salt"], keys["private_key_iv"])
        except Exception:
            audit("CONTRACT_SIGN_FAIL", contract_id=contract_id, success=False)
            flash("Password inválida para decifrar a chave privada.", "danger")
            return render_template("sign_contract.html", contract=contract)
        signature = crypto.sign_payload(private_pem, crypto.canonical_contract_payload(contract))
        db.save_signature(contract_id, session["user_id"], signature)
        audit("CONTRACT_SIGNED", contract_id=contract_id)
        flash("Contrato assinado digitalmente.", "success")
        return redirect(url_for("view_contract", contract_id=contract_id))
    return render_template("sign_contract.html", contract=contract)


@app.route("/contracts/<int:contract_id>/verify")
def verify_contract(contract_id: int):
    contract = db.get_contract(contract_id)
    if not contract:
        flash("Contrato não encontrado.", "danger")
        return redirect(url_for("contracts_list"))
    denied = deny_if_cannot_view(contract)
    if denied:
        return denied
    rows = []
    for sig in db.get_contract_signatures(contract_id):
        rows.append({**sig, "valid": crypto.verify_signature(sig["public_key"], crypto.canonical_contract_payload(contract), sig["assinatura_digital"])})
    audit("SIGNATURE_VERIFIED", contract_id=contract_id)
    return render_template("verify.html", contract=contract, signatures=rows)


@app.route("/verify", methods=["GET", "POST"])
def verify_manual():
    result = None
    if request.method == "POST":
        public_key = request.form.get("public_key", "")
        payload = request.form.get("payload", "")
        signature = request.form.get("signature", "")
        result = crypto.verify_signature(public_key, payload.encode("utf-8"), signature)
        audit("MANUAL_SIGNATURE_VERIFY", success=bool(result))
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
    contracts = contracts_for_display(db.get_profile_contracts(user_id, _current_user_id()))
    return render_template("profile.html", user=user, keys=keys, contracts=contracts)


@app.route("/contracts/<int:contract_id>/settle", methods=["POST"])
@login_required
def settle_contract(contract_id: int):
    contract = db.get_contract(contract_id)
    if not contract:
        flash("Contrato não encontrado.", "danger")
        return redirect(url_for("contracts_list"))
    if session["user_id"] != contract["id_aceitante"]:
        flash("Só o aceitante pode marcar este contrato como sanado.", "danger")
        return redirect(url_for("view_contract", contract_id=contract_id))
    if contract["estado"] != "assinado":
        flash("Só contratos assinados podem ser marcados como sanados.", "warning")
        return redirect(url_for("view_contract", contract_id=contract_id))
    db.mark_sanado(contract_id)
    audit("CONTRACT_SETTLED", contract_id=contract_id)
    flash("Contrato marcado como sanado.", "success")
    return redirect(url_for("view_contract", contract_id=contract_id))


@app.route("/contracts/<int:contract_id>/reject", methods=["POST"])
@login_required
def reject_contract(contract_id: int):
    contract = db.get_contract(contract_id)
    if not contract:
        flash("Contrato não encontrado.", "danger")
        return redirect(url_for("contracts_list"))
    if not _is_contract_party(contract, session["user_id"]):
        flash("Não fazes parte deste contrato.", "danger")
        return redirect(url_for("contracts_list"))
    if contract["estado"] != "pendente":
        flash("Só contratos pendentes podem ser rejeitados.", "warning")
        return redirect(url_for("view_contract", contract_id=contract_id))
    db.mark_rejeitado(contract_id)
    audit("CONTRACT_REJECTED", contract_id=contract_id)
    flash("Contrato rejeitado.", "success")
    return redirect(url_for("view_contract", contract_id=contract_id))


@app.route("/contracts/<int:contract_id>/hmac", methods=["POST"])
@login_required
def verify_contract_hmac(contract_id: int):
    contract = db.get_contract(contract_id)
    if not contract:
        flash("Contrato não encontrado.", "danger")
        return redirect(url_for("contracts_list"))
    if not _is_contract_party(contract, session["user_id"]):
        flash("Só as partes podem verificar o HMAC com password.", "danger")
        return redirect(url_for("view_contract", contract_id=contract_id))
    if not contract.get("encrypted_text"):
        flash("Este contrato não tem texto cifrado.", "warning")
        return redirect(url_for("view_contract", contract_id=contract_id))
    password = request.form.get("password", "")
    ok = crypto.verify_contract_hmac(contract["encrypted_text"], password, contract["encryption_salt"], contract["encryption_iv"], contract["encryption_algorithm"], contract["hmac_algorithm"], contract["hmac_value"])
    audit("CONTRACT_HMAC_VERIFIED" if ok else "CONTRACT_HMAC_FAILED", contract_id=contract_id, success=ok)
    flash("HMAC válido: criptograma, IV e algoritmo não foram alterados." if ok else "HMAC inválido ou password errada.", "success" if ok else "danger")
    return redirect(url_for("view_contract", contract_id=contract_id))


@app.route("/contracts/<int:contract_id>/export")
def export_contract(contract_id: int):
    raw_contract = db.get_contract(contract_id)
    if not raw_contract:
        flash("Contrato não encontrado.", "danger")
        return redirect(url_for("contracts_list"))
    denied = deny_if_cannot_view(raw_contract)
    if denied:
        return denied
    contract = dict(raw_contract)
    if contract.get("encrypted_text") and not public_reveal_time_reached(contract):
        contract["texto_contrato"] = f"[Texto cifrado até {contract.get('reveal_at')}]"
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["campo", "valor"])
    for key in ["id", "titulo", "texto_contrato", "id_proponente", "id_aceitante", "estado", "visibilidade", "data_criacao", "encrypted_text", "encryption_algorithm", "hmac_algorithm", "encryption_salt", "encryption_iv", "hmac_value", "reveal_at"]:
        writer.writerow([key, contract.get(key)])
    writer.writerow([])
    writer.writerow(["canonical_payload", crypto.canonical_contract_payload(raw_contract).decode("utf-8")])
    writer.writerow([])
    writer.writerow(["assinante", "tipo", "assinatura", "public_key"])
    for s in db.get_contract_signatures(contract_id):
        writer.writerow([s["email"], s["tipo_assinante"], s["assinatura_digital"], s["public_key"]])
    audit("CONTRACT_EXPORTED_CSV", contract_id=contract_id)
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename=contract_{contract_id}.csv"})


@app.route("/contracts/<int:contract_id>/export/openssl.zip")
def export_contract_openssl_zip(contract_id: int):
    contract = db.get_contract(contract_id)
    if not contract:
        flash("Contrato não encontrado.", "danger")
        return redirect(url_for("contracts_list"))
    denied = deny_if_cannot_view(contract)
    if denied:
        return denied
    payload = crypto.canonical_contract_payload(contract)
    signatures = db.get_contract_signatures(contract_id)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("payload.txt", payload)
        readme = [
            "EU-PAGOTAMANHA - verificação externa OpenSSL", "",
            "1) Converter assinatura Base64 para binário, se necessário:",
            "   openssl base64 -d -in signature_proponente.b64 -out signature_proponente.bin", "",
            "2) Verificar assinatura RSA-PSS/SHA256:",
            "   openssl dgst -sha256 -verify public_key_proponente.pem -signature signature_proponente.bin -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-2 -sigopt rsa_mgf1_md:sha256 payload.txt", "",
            "Repetir para o aceitante substituindo os nomes dos ficheiros.", "",
            "Payload assinado = id_proponente, id_aceitante, texto_contrato e data_criacao, separados por newline.",
        ]
        zf.writestr("README_verificacao.txt", "\n".join(readme))
        for sig in signatures:
            role = sig["tipo_assinante"]
            zf.writestr(f"public_key_{role}.pem", sig["public_key"] or "")
            zf.writestr(f"signature_{role}.b64", sig["assinatura_digital"] or "")
            if sig.get("assinatura_digital"):
                try:
                    zf.writestr(f"signature_{role}.bin", base64.b64decode(sig["assinatura_digital"]))
                except Exception:
                    zf.writestr(f"signature_{role}.bin", b"")
    buffer.seek(0)
    audit("CONTRACT_EXPORTED_OPENSSL_ZIP", contract_id=contract_id)
    return Response(buffer.getvalue(), mimetype="application/zip", headers={"Content-Disposition": f"attachment; filename=contract_{contract_id}_openssl.zip"})


# aliases para templates antigos
home = index
contract_detail = view_contract


if __name__ == "__main__":
    db.init_db()
    app.run(host=os.getenv("BIND_HOST", "127.0.0.1"), port=int(os.getenv("BIND_PORT", "5000")), debug=True)
