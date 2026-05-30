from __future__ import annotations

import os
from contextlib import contextmanager
from datetime import datetime
from typing import Any

import pymysql
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv()

HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
PORT = int(os.getenv("MYSQL_PORT", "3306"))
DB_NAME = os.getenv("MYSQL_DATABASE", "EUPagoAmanhaDB")
USER = os.getenv("MYSQL_USERNAME", "root")
PASSWORD = os.getenv("MYSQL_PASSWORD", "")


def _connect(database: str | None = DB_NAME):
    kwargs = dict(
        host=HOST,
        port=PORT,
        user=USER,
        password=PASSWORD,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
    )
    if database:
        kwargs["database"] = database
    return pymysql.connect(**kwargs)


@contextmanager
def get_db():
    conn = _connect(DB_NAME)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    root = _connect(None)
    try:
        with root.cursor() as cur:
            cur.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        root.commit()
    finally:
        root.close()

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS utilizadores (
                id INT AUTO_INCREMENT PRIMARY KEY,
                nome VARCHAR(120) NOT NULL,
                email VARCHAR(180) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                data_registo DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                mfa_secret VARCHAR(255) NULL,
                password_changed_at DATETIME NULL,
                must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
                INDEX idx_utilizadores_email (email)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS chaves_utilizador (
                id INT AUTO_INCREMENT PRIMARY KEY,
                id_utilizador INT NOT NULL UNIQUE,
                public_key LONGTEXT NOT NULL,
                encrypted_private_key LONGTEXT NOT NULL,
                private_key_salt VARCHAR(255) NOT NULL,
                private_key_iv VARCHAR(255) NOT NULL,
                private_key_algorithm VARCHAR(50) NOT NULL DEFAULT 'AES-256-CBC',
                data_criacao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT fk_chaves_user FOREIGN KEY (id_utilizador)
                    REFERENCES utilizadores(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS contratos (
                id INT AUTO_INCREMENT PRIMARY KEY,
                titulo VARCHAR(180) NOT NULL,
                texto_contrato LONGTEXT NOT NULL,
                id_proponente INT NOT NULL,
                id_aceitante INT NOT NULL,
                estado ENUM('pendente','assinado','sanado','rejeitado') NOT NULL DEFAULT 'pendente',
                visibilidade ENUM('publico','privado') NOT NULL DEFAULT 'publico',
                data_criacao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                data_atualizacao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                encrypted_text LONGTEXT NULL,
                encryption_iv VARCHAR(255) NULL,
                encryption_salt VARCHAR(255) NULL,
                encryption_algorithm VARCHAR(50) NULL,
                hmac_algorithm VARCHAR(50) NULL,
                hmac_value LONGTEXT NULL,
                reveal_at DATETIME NULL,
                CONSTRAINT fk_contratos_prop FOREIGN KEY (id_proponente)
                    REFERENCES utilizadores(id) ON DELETE CASCADE,
                CONSTRAINT fk_contratos_aceit FOREIGN KEY (id_aceitante)
                    REFERENCES utilizadores(id) ON DELETE CASCADE,
                INDEX idx_contratos_estado (estado),
                INDEX idx_contratos_prop (id_proponente),
                INDEX idx_contratos_aceit (id_aceitante)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS assinaturas_contrato (
                id INT AUTO_INCREMENT PRIMARY KEY,
                id_contrato INT NOT NULL,
                id_utilizador INT NOT NULL,
                tipo_assinante ENUM('proponente','aceitante') NOT NULL,
                assinatura_digital LONGTEXT NULL,
                data_assinatura DATETIME NULL,
                CONSTRAINT fk_assinaturas_contrato FOREIGN KEY (id_contrato)
                    REFERENCES contratos(id) ON DELETE CASCADE,
                CONSTRAINT fk_assinaturas_user FOREIGN KEY (id_utilizador)
                    REFERENCES utilizadores(id) ON DELETE CASCADE,
                UNIQUE KEY uq_assinatura_parte (id_contrato, id_utilizador, tipo_assinante)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS password_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                id_utilizador INT NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                data_criacao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT fk_password_history_user FOREIGN KEY (id_utilizador)
                    REFERENCES utilizadores(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)


def create_user(nome: str, email: str, password_hash: str, key_data: dict[str, str]) -> int:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO utilizadores (nome, email, password_hash, password_changed_at) VALUES (%s, %s, %s, NOW())",
            (nome, email, password_hash),
        )
        user_id = cur.lastrowid
        cur.execute(
            """
            INSERT INTO chaves_utilizador
            (id_utilizador, public_key, encrypted_private_key, private_key_salt, private_key_iv, private_key_algorithm)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                user_id,
                key_data["public_key"],
                key_data["encrypted_private_key"],
                key_data["private_key_salt"],
                key_data["private_key_iv"],
                key_data.get("private_key_algorithm", "AES-256-CBC"),
            ),
        )
        cur.execute("INSERT INTO password_history (id_utilizador, password_hash) VALUES (%s, %s)", (user_id, password_hash))
        return int(user_id)


def get_user_by_email(email: str) -> dict | None:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM utilizadores WHERE email = %s", (email,))
        return cur.fetchone()


def get_user(user_id: int) -> dict | None:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM utilizadores WHERE id = %s", (user_id,))
        return cur.fetchone()


def get_user_keys(user_id: int) -> dict | None:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM chaves_utilizador WHERE id_utilizador = %s", (user_id,))
        return cur.fetchone()


def list_users(exclude_id: int | None = None) -> list[dict]:
    with get_db() as conn:
        cur = conn.cursor()
        if exclude_id:
            cur.execute("SELECT id, nome, email, data_registo FROM utilizadores WHERE id <> %s ORDER BY nome", (exclude_id,))
        else:
            cur.execute("SELECT id, nome, email, data_registo FROM utilizadores ORDER BY nome")
        return list(cur.fetchall())


def create_contract(data: dict[str, Any]) -> int:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO contratos
            (titulo, texto_contrato, id_proponente, id_aceitante, estado, visibilidade, data_criacao,
             encrypted_text, encryption_iv, encryption_salt, encryption_algorithm, hmac_algorithm, hmac_value, reveal_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                data["titulo"], data["texto_contrato"], data["id_proponente"], data["id_aceitante"],
                data.get("estado", "pendente"), data.get("visibilidade", "publico"), data["data_criacao"],
                data.get("encrypted_text"), data.get("encryption_iv"), data.get("encryption_salt"),
                data.get("encryption_algorithm"), data.get("hmac_algorithm"), data.get("hmac_value"), data.get("reveal_at"),
            ),
        )
        contract_id = int(cur.lastrowid)
        cur.execute(
            """
            INSERT INTO assinaturas_contrato
            (id_contrato, id_utilizador, tipo_assinante, assinatura_digital, data_assinatura)
            VALUES (%s, %s, 'proponente', %s, %s)
            """,
            (contract_id, data["id_proponente"], data.get("proponente_signature"), data.get("proponente_signed_at")),
        )
        cur.execute(
            """
            INSERT INTO assinaturas_contrato
            (id_contrato, id_utilizador, tipo_assinante, assinatura_digital, data_assinatura)
            VALUES (%s, %s, 'aceitante', NULL, NULL)
            """,
            (contract_id, data["id_aceitante"]),
        )
        return contract_id


def _contract_select(extra_where: str = "", params: tuple = ()) -> list[dict]:
    with get_db() as conn:
        cur = conn.cursor()
        sql = f"""
            SELECT c.*,
                   p.nome AS proponente_nome, p.email AS proponente_email,
                   a.nome AS aceitante_nome, a.email AS aceitante_email,
                   (SELECT COUNT(*) FROM assinaturas_contrato s WHERE s.id_contrato=c.id AND s.assinatura_digital IS NOT NULL) AS assinaturas_count
            FROM contratos c
            JOIN utilizadores p ON p.id = c.id_proponente
            JOIN utilizadores a ON a.id = c.id_aceitante
            {extra_where}
            ORDER BY c.data_criacao DESC, c.id DESC
        """
        cur.execute(sql, params)
        return list(cur.fetchall())


def get_public_contracts() -> list[dict]:
    return _contract_select("WHERE c.visibilidade='publico' AND c.estado IN ('assinado','sanado')")


def get_visible_contracts(viewer_id: int | None = None) -> list[dict]:
    """Contracts visible in the public ledger for the current viewer.

    Anonymous users see only public contracts that are already signed or settled.
    Authenticated users also see contracts where they are one of the two parties,
    including private, pending and rejected contracts.
    """
    if not viewer_id:
        return get_public_contracts()
    return _contract_select(
        """
        WHERE (c.visibilidade='publico' AND c.estado IN ('assinado','sanado'))
           OR c.id_proponente=%s
           OR c.id_aceitante=%s
        """,
        (viewer_id, viewer_id),
    )


def get_visible_user_contracts(profile_user_id: int, viewer_id: int | None = None) -> list[dict]:
    """Contracts shown on a public user profile for the current viewer."""
    if not viewer_id:
        return _contract_select(
            """
            WHERE (c.id_proponente=%s OR c.id_aceitante=%s)
              AND c.visibilidade='publico'
              AND c.estado IN ('assinado','sanado')
            """,
            (profile_user_id, profile_user_id),
        )
    return _contract_select(
        """
        WHERE (c.id_proponente=%s OR c.id_aceitante=%s)
          AND (
              (c.visibilidade='publico' AND c.estado IN ('assinado','sanado'))
              OR c.id_proponente=%s
              OR c.id_aceitante=%s
          )
        """,
        (profile_user_id, profile_user_id, viewer_id, viewer_id),
    )


def get_all_contracts() -> list[dict]:
    # Kept for admin/debug scripts. Do not use directly in public routes.
    return _contract_select()


def get_user_contracts(user_id: int) -> list[dict]:
    return _contract_select("WHERE c.id_proponente=%s OR c.id_aceitante=%s", (user_id, user_id))


def get_contract(contract_id: int) -> dict | None:
    rows = _contract_select("WHERE c.id=%s", (contract_id,))
    return rows[0] if rows else None


def get_contract_signatures(contract_id: int) -> list[dict]:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT s.*, u.nome, u.email, k.public_key
            FROM assinaturas_contrato s
            JOIN utilizadores u ON u.id=s.id_utilizador
            JOIN chaves_utilizador k ON k.id_utilizador=u.id
            WHERE s.id_contrato=%s
            ORDER BY FIELD(s.tipo_assinante, 'proponente', 'aceitante')
            """,
            (contract_id,),
        )
        return list(cur.fetchall())


def save_signature(contract_id: int, user_id: int, signature: str) -> None:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE assinaturas_contrato
            SET assinatura_digital=%s, data_assinatura=NOW()
            WHERE id_contrato=%s AND id_utilizador=%s
            """,
            (signature, contract_id, user_id),
        )
        cur.execute("SELECT COUNT(*) AS total FROM assinaturas_contrato WHERE id_contrato=%s AND assinatura_digital IS NOT NULL", (contract_id,))
        signed = cur.fetchone()["total"]
        if signed >= 2:
            cur.execute("UPDATE contratos SET estado='assinado' WHERE id=%s", (contract_id,))


def mark_sanado(contract_id: int) -> None:
    with get_db() as conn:
        conn.cursor().execute("UPDATE contratos SET estado='sanado' WHERE id=%s", (contract_id,))


def seed_basic() -> None:
    # Used by scripts/reset_and_seed.py; kept here for convenience.
    pass


def mark_rejeitado(contract_id: int) -> None:
    with get_db() as conn:
        conn.cursor().execute("UPDATE contratos SET estado='rejeitado' WHERE id=%s AND estado='pendente'", (contract_id,))

def set_mfa(user_id: int, enabled: bool, secret: str | None = None) -> None:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE utilizadores
            SET mfa_enabled=%s, mfa_secret=%s
            WHERE id=%s
            """,
            (enabled, secret, user_id),
        )