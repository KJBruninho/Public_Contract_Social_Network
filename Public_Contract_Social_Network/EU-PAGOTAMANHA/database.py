from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any

import pymysql
from dotenv import load_dotenv

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


def _ensure_column(cur, table: str, column: str, ddl: str) -> None:
    cur.execute(f"SHOW COLUMNS FROM `{table}` LIKE %s", (column,))
    if not cur.fetchone():
        cur.execute(f"ALTER TABLE `{table}` ADD COLUMN {ddl}")


def _ensure_index(cur, table: str, index_name: str, ddl: str) -> None:
    cur.execute("""
        SELECT COUNT(*) AS total
        FROM information_schema.statistics
        WHERE table_schema=%s AND table_name=%s AND index_name=%s
    """, (DB_NAME, table, index_name))
    if cur.fetchone()["total"] == 0:
        cur.execute(ddl)


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
        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INT AUTO_INCREMENT PRIMARY KEY,
                id_utilizador INT NULL,
                email VARCHAR(180) NULL,
                acao VARCHAR(80) NOT NULL,
                id_contrato INT NULL,
                sucesso BOOLEAN NOT NULL DEFAULT TRUE,
                detalhes TEXT NULL,
                ip_address VARCHAR(64) NULL,
                user_agent VARCHAR(255) NULL,
                data_evento DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_audit_user (id_utilizador),
                INDEX idx_audit_email (email),
                INDEX idx_audit_action (acao),
                INDEX idx_audit_contract (id_contrato),
                INDEX idx_audit_date (data_evento),
                CONSTRAINT fk_audit_user FOREIGN KEY (id_utilizador)
                    REFERENCES utilizadores(id) ON DELETE SET NULL,
                CONSTRAINT fk_audit_contract FOREIGN KEY (id_contrato)
                    REFERENCES contratos(id) ON DELETE SET NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)

        # Lightweight migrations for older databases created before these fields existed.
        _ensure_column(cur, "utilizadores", "mfa_enabled", "mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE")
        _ensure_column(cur, "utilizadores", "mfa_secret", "mfa_secret VARCHAR(255) NULL")
        _ensure_column(cur, "utilizadores", "password_changed_at", "password_changed_at DATETIME NULL")
        _ensure_column(cur, "utilizadores", "must_change_password", "must_change_password BOOLEAN NOT NULL DEFAULT FALSE")
        _ensure_column(cur, "contratos", "visibilidade", "visibilidade ENUM('publico','privado') NOT NULL DEFAULT 'publico'")
        _ensure_column(cur, "contratos", "encrypted_text", "encrypted_text LONGTEXT NULL")
        _ensure_column(cur, "contratos", "encryption_iv", "encryption_iv VARCHAR(255) NULL")
        _ensure_column(cur, "contratos", "encryption_salt", "encryption_salt VARCHAR(255) NULL")
        _ensure_column(cur, "contratos", "encryption_algorithm", "encryption_algorithm VARCHAR(50) NULL")
        _ensure_column(cur, "contratos", "hmac_algorithm", "hmac_algorithm VARCHAR(50) NULL")
        _ensure_column(cur, "contratos", "hmac_value", "hmac_value LONGTEXT NULL")
        _ensure_column(cur, "contratos", "reveal_at", "reveal_at DATETIME NULL")
        cur.execute("UPDATE utilizadores SET password_changed_at=COALESCE(password_changed_at, data_registo, NOW())")


def create_user(nome: str, email: str, password_hash: str, key_data: dict[str, str]) -> int:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO utilizadores (nome, email, password_hash, password_changed_at) VALUES (%s, %s, %s, NOW())",
            (nome, email, password_hash),
        )
        user_id = int(cur.lastrowid)
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
        return user_id


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


def set_mfa(user_id: int, enabled: bool, secret: str | None = None) -> None:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE utilizadores SET mfa_enabled=%s, mfa_secret=%s WHERE id=%s",
            (enabled, secret, user_id),
        )


def get_password_history(user_id: int, limit: int = 3) -> list[dict]:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT password_hash, data_criacao
            FROM password_history
            WHERE id_utilizador=%s
            ORDER BY data_criacao DESC, id DESC
            LIMIT %s
            """,
            (user_id, limit),
        )
        return list(cur.fetchall())


def update_user_password_and_keys(user_id: int, password_hash: str, key_data: dict[str, str]) -> None:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE utilizadores
            SET password_hash=%s, password_changed_at=NOW(), must_change_password=FALSE
            WHERE id=%s
            """,
            (password_hash, user_id),
        )
        cur.execute(
            """
            UPDATE chaves_utilizador
            SET encrypted_private_key=%s, private_key_salt=%s, private_key_iv=%s, private_key_algorithm=%s
            WHERE id_utilizador=%s
            """,
            (
                key_data["encrypted_private_key"],
                key_data["private_key_salt"],
                key_data["private_key_iv"],
                key_data.get("private_key_algorithm", "AES-256-CBC"),
                user_id,
            ),
        )
        cur.execute("INSERT INTO password_history (id_utilizador, password_hash) VALUES (%s, %s)", (user_id, password_hash))


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
    if viewer_id:
        return _contract_select(
            """
            WHERE (c.visibilidade='publico' AND c.estado IN ('assinado','sanado'))
               OR c.id_proponente=%s
               OR c.id_aceitante=%s
            """,
            (viewer_id, viewer_id),
        )
    return get_public_contracts()


def get_all_contracts() -> list[dict]:
    return _contract_select()


def get_user_contracts(user_id: int) -> list[dict]:
    return _contract_select("WHERE c.id_proponente=%s OR c.id_aceitante=%s", (user_id, user_id))


def get_profile_contracts(profile_user_id: int, viewer_id: int | None = None) -> list[dict]:
    if viewer_id == profile_user_id:
        return get_user_contracts(profile_user_id)
    if viewer_id:
        return _contract_select(
            """
            WHERE (c.id_proponente=%s OR c.id_aceitante=%s)
              AND ((c.visibilidade='publico' AND c.estado IN ('assinado','sanado'))
                   OR c.id_proponente=%s OR c.id_aceitante=%s)
            """,
            (profile_user_id, profile_user_id, viewer_id, viewer_id),
        )
    return _contract_select(
        """
        WHERE (c.id_proponente=%s OR c.id_aceitante=%s)
          AND c.visibilidade='publico' AND c.estado IN ('assinado','sanado')
        """,
        (profile_user_id, profile_user_id),
    )


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


def mark_rejeitado(contract_id: int) -> None:
    with get_db() as conn:
        conn.cursor().execute("UPDATE contratos SET estado='rejeitado' WHERE id=%s AND estado='pendente'", (contract_id,))


def add_audit_log(
    action: str,
    user_id: int | None = None,
    email: str | None = None,
    contract_id: int | None = None,
    success: bool = True,
    details: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO audit_log
            (id_utilizador, email, acao, id_contrato, sucesso, detalhes, ip_address, user_agent)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (user_id, email, action, contract_id, success, details, ip_address, (user_agent or "")[:255]),
        )


def count_recent_failed_logins(email: str, ip_address: str | None, window_minutes: int = 5) -> int:
    window_minutes = max(1, min(int(window_minutes), 1440))
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT COUNT(*) AS total
            FROM audit_log
            WHERE acao='LOGIN_FAIL'
              AND sucesso=FALSE
              AND data_evento >= DATE_SUB(NOW(), INTERVAL {window_minutes} MINUTE)
              AND (email=%s OR ip_address=%s)
            """,
            (email, ip_address),
        )
        return int(cur.fetchone()["total"])


def get_user_audit_logs(user_id: int, limit: int = 50) -> list[dict]:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT * FROM audit_log
            WHERE id_utilizador=%s
            ORDER BY data_evento DESC, id DESC
            LIMIT %s
            """,
            (user_id, limit),
        )
        return list(cur.fetchall())


def get_contract_audit_logs(contract_id: int, limit: int = 30) -> list[dict]:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT l.*, u.nome, u.email AS user_email
            FROM audit_log l
            LEFT JOIN utilizadores u ON u.id=l.id_utilizador
            WHERE l.id_contrato=%s
            ORDER BY l.data_evento DESC, l.id DESC
            LIMIT %s
            """,
            (contract_id, limit),
        )
        return list(cur.fetchall())


def get_security_stats(user_id: int) -> dict:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS total FROM audit_log WHERE id_utilizador=%s AND acao='LOGIN_OK'", (user_id,))
        logins = int(cur.fetchone()["total"])
        cur.execute("SELECT COUNT(*) AS total FROM audit_log WHERE id_utilizador=%s AND sucesso=FALSE", (user_id,))
        failures = int(cur.fetchone()["total"])
        cur.execute("SELECT COUNT(*) AS total FROM audit_log WHERE id_utilizador=%s AND acao='CONTRACT_EXPORTED_OPENSSL_ZIP'", (user_id,))
        exports = int(cur.fetchone()["total"])
        return {"logins": logins, "failures": failures, "openssl_exports": exports}


def update_contract_text_for_demo(contract_id: int, new_text: str) -> None:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE contratos SET texto_contrato=%s WHERE id=%s", (new_text, contract_id))


def seed_basic() -> None:
    # Used by scripts/reset_and_seed.py; kept here for convenience.
    pass
