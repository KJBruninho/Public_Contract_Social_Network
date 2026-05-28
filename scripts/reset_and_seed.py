from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from werkzeug.security import generate_password_hash  # noqa: E402
import crypto_utils as crypto  # noqa: E402
import database as db  # noqa: E402

PASSWORD = "password"


def clear():
    with db.get_db() as conn:
        cur = conn.cursor()
        cur.execute("SET FOREIGN_KEY_CHECKS=0")
        for table in ["assinaturas_contrato", "contratos", "chaves_utilizador", "password_history", "utilizadores"]:
            cur.execute(f"TRUNCATE TABLE {table}")
        cur.execute("SET FOREIGN_KEY_CHECKS=1")


def create_user(nome, email):
    private_pem, public_pem = crypto.generate_rsa_keypair()
    encrypted = crypto.encrypt_private_key(private_pem, PASSWORD)
    return db.create_user(nome, email, generate_password_hash(PASSWORD, method="scrypt", salt_length=16), {"public_key": public_pem, **encrypted})


def sign_as(contract, user_id):
    keys = db.get_user_keys(user_id)
    private_pem = crypto.decrypt_private_key(keys["encrypted_private_key"], PASSWORD, keys["private_key_salt"], keys["private_key_iv"])
    sig = crypto.sign_payload(private_pem, crypto.canonical_contract_payload(contract))
    db.save_signature(contract["id"], user_id, sig)


def create_contract(title, text, prop, aceit, signed_by_acceptant=True, encrypted=False):
    created_at = datetime.now().replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")
    keys = db.get_user_keys(prop)
    private_pem = crypto.decrypt_private_key(keys["encrypted_private_key"], PASSWORD, keys["private_key_salt"], keys["private_key_iv"])
    payload = {"id_proponente": prop, "id_aceitante": aceit, "texto_contrato": text, "data_criacao": created_at}
    data = {
        "titulo": title,
        "texto_contrato": text,
        "id_proponente": prop,
        "id_aceitante": aceit,
        "estado": "pendente",
        "visibilidade": "publico",
        "data_criacao": created_at,
        "proponente_signature": crypto.sign_payload(private_pem, crypto.canonical_contract_payload(payload)),
        "proponente_signed_at": created_at,
    }
    if encrypted:
        data.update(crypto.encrypt_contract_text(text, PASSWORD, "AES-256-CBC", "HMAC-SHA256"))
        data["reveal_at"] = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    cid = db.create_contract(data)
    if signed_by_acceptant:
        sign_as(db.get_contract(cid), aceit)
    return cid


if __name__ == "__main__":
    db.init_db()
    clear()
    ana = create_user("Ana Silva", "ana@example.com")
    bruno = create_user("Bruno Costa", "bruno@example.com")
    carla = create_user("Carla Mendes", "carla@example.com")
    diogo = create_user("Diogo Ferreira", "diogo@example.com")

    create_contract("Empréstimo de 10 euros", "Devo-te 10 euros mas juro que te pago amanhã!", ana, bruno, True)
    create_contract("Pagamento de renda partilhada", "Comprometo-me a transferir 120 euros referentes à renda partilhada até sexta-feira.", diogo, ana, True)
    create_contract("Bilhete de concerto", "A Carla adianta 35 euros pelo bilhete e a Ana paga até ao final do mês.", ana, carla, False)
    create_contract("Contrato temporariamente cifrado", "Este contrato fica cifrado durante uma semana, mas o criptograma é público.", carla, diogo, False, True)
    print("Base de dados populada.")
    print("Credenciais: ana@example.com / password | bruno@example.com / password | carla@example.com / password | diogo@example.com / password")
