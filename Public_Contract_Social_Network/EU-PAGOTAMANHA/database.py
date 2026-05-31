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


REQUIRED_TABLES = [
    "utilizadores",
    "chaves_utilizador",
    "contratos",
    "assinaturas_contrato",
    "password_history",
    "audit_log",
]

REQUIRED_VIEWS = [
    "v_contratos_com_partes",
    "v_contratos_publicos",
    "v_user_security_stats",
]

REQUIRED_PROCEDURES = [
    "sp_save_signature",
    "sp_mark_sanado",
    "sp_mark_rejeitado",
    "sp_add_audit_log",
    "sp_set_mfa",
    "sp_count_recent_failed_logins",
    "sp_create_contract",
]

REQUIRED_TRIGGERS = [
    "trg_contrato_no_self_contract_bi",
    "trg_contrato_no_self_contract_bu",
    "trg_contrato_reveal_at_check_bi",
    "trg_contrato_reveal_at_check_bu",
    "trg_assinatura_after_insert",
    "trg_assinatura_after_update",
]


def _connect(database: str | None = DB_NAME):
    kwargs = {
        "host": HOST,
        "port": PORT,
        "user": USER,
        "password": PASSWORD,
        "charset": "utf8mb4",
        "cursorclass": pymysql.cursors.DictCursor,
        "autocommit": False,
    }
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
    """Valida que a BD foi criada pelos scripts SQL antes de arrancar a app."""

    with get_db() as conn:
        cur = conn.cursor()

        for table in REQUIRED_TABLES:
            cur.execute(
                """
                SELECT COUNT(*) AS total
                FROM information_schema.tables
                WHERE table_schema=%s
                  AND table_name=%s
                  AND table_type='BASE TABLE'
                """,
                (DB_NAME, table),
            )
            if cur.fetchone()["total"] == 0:
                raise RuntimeError(
                    f"Tabela obrigatória em falta: {table}. "
                    "Executa init.sql da BD."
                )

        for view in REQUIRED_VIEWS:
            cur.execute(
                """
                SELECT COUNT(*) AS total
                FROM information_schema.views
                WHERE table_schema=%s
                  AND table_name=%s
                """,
                (DB_NAME, view),
            )
            if cur.fetchone()["total"] == 0:
                raise RuntimeError(
                    f"View obrigatória em falta: {view}. "
                    "Executa init.sql da BD."
                )

        for procedure in REQUIRED_PROCEDURES:
            cur.execute(
                """
                SELECT COUNT(*) AS total
                FROM information_schema.routines
                WHERE routine_schema=%s
                  AND routine_name=%s
                  AND routine_type='PROCEDURE'
                """,
                (DB_NAME, procedure),
            )
            if cur.fetchone()["total"] == 0:
                raise RuntimeError(
                    f"Procedure obrigatória em falta: {procedure}. "
                    "Executa init.sql da BD."
                )

        for trigger in REQUIRED_TRIGGERS:
            cur.execute(
                """
                SELECT COUNT(*) AS total
                FROM information_schema.triggers
                WHERE trigger_schema=%s
                  AND trigger_name=%s
                """,
                (DB_NAME, trigger),
            )
            if cur.fetchone()["total"] == 0:
                raise RuntimeError(
                    f"Trigger obrigatório em falta: {trigger}. "
                    "Executa init.sql da BD."
                )


# ---------------------------------------------------------------------------
# Utilizadores e chaves
# ---------------------------------------------------------------------------

def create_user(nome: str, email: str, password_hash: str, key_data: dict[str, str]) -> int:
    """Cria utilizador, guarda par de chaves e regista a password inicial."""

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO utilizadores
            (nome, email, password_hash, password_changed_at)
            VALUES (%s, %s, %s, NOW())
            """,
            (nome, email, password_hash),
        )
        user_id = int(cur.lastrowid)

        cur.execute(
            """
            INSERT INTO chaves_utilizador
            (id_utilizador, public_key, encrypted_private_key,
             private_key_salt, private_key_iv, private_key_algorithm)
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

        cur.execute(
            """
            INSERT INTO password_history (id_utilizador, password_hash)
            VALUES (%s, %s)
            """,
            (user_id, password_hash),
        )

        return user_id


def get_user_by_email(email: str) -> dict | None:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM utilizadores WHERE email=%s", (email,))
        return cur.fetchone()


def get_user(user_id: int) -> dict | None:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM utilizadores WHERE id=%s", (user_id,))
        return cur.fetchone()


def get_user_keys(user_id: int) -> dict | None:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM chaves_utilizador WHERE id_utilizador=%s", (user_id,))
        return cur.fetchone()


def list_users(exclude_id: int | None = None) -> list[dict]:
    with get_db() as conn:
        cur = conn.cursor()
        if exclude_id:
            cur.execute(
                """
                SELECT id, nome, email, data_registo
                FROM utilizadores
                WHERE id <> %s
                ORDER BY nome
                """,
                (exclude_id,),
            )
        else:
            cur.execute(
                """
                SELECT id, nome, email, data_registo
                FROM utilizadores
                ORDER BY nome
                """
            )
        return list(cur.fetchall())


def set_mfa(user_id: int, enabled: bool, secret: str | None = None) -> None:
    with get_db() as conn:
        conn.cursor().callproc("sp_set_mfa", (user_id, enabled, secret))


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
    """Atualiza password e recifra a chave privada com a nova password."""

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE utilizadores
            SET password_hash=%s,
                password_changed_at=NOW(),
                must_change_password=FALSE
            WHERE id=%s
            """,
            (password_hash, user_id),
        )

        cur.execute(
            """
            UPDATE chaves_utilizador
            SET encrypted_private_key=%s,
                private_key_salt=%s,
                private_key_iv=%s,
                private_key_algorithm=%s
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

        cur.execute(
            """
            INSERT INTO password_history (id_utilizador, password_hash)
            VALUES (%s, %s)
            """,
            (user_id, password_hash),
        )


# ---------------------------------------------------------------------------
# Contratos
# ---------------------------------------------------------------------------

def create_contract(data: dict[str, Any]) -> int:
    """Cria contrato e assinaturas iniciais através da procedure da BD."""

    with get_db() as conn:
        cur = conn.cursor()
        cur.callproc(
            "sp_create_contract",
            (
                data["titulo"],
                data["texto_contrato"],
                data["id_proponente"],
                data["id_aceitante"],
                data.get("estado", "pendente"),
                data.get("visibilidade", "publico"),
                data["data_criacao"],
                data.get("encrypted_text"),
                data.get("encryption_iv"),
                data.get("encryption_salt"),
                data.get("encryption_algorithm"),
                data.get("hmac_algorithm"),
                data.get("hmac_value"),
                data.get("reveal_at"),
                data.get("proponente_signature"),
                data.get("proponente_signed_at"),
            ),
        )
        row = cur.fetchone()
        if not row:
            raise RuntimeError("sp_create_contract não devolveu contract_id.")
        return int(row["contract_id"])


def _contract_select(extra_where: str = "", params: tuple = ()) -> list[dict]:
    with get_db() as conn:
        cur = conn.cursor()
        sql = f"""
            SELECT c.*
            FROM v_contratos_com_partes c
            {extra_where}
            ORDER BY c.data_criacao DESC, c.id DESC
        """
        cur.execute(sql, params)
        return list(cur.fetchall())


def get_public_contracts() -> list[dict]:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM v_contratos_publicos ORDER BY data_criacao DESC, id DESC")
        return list(cur.fetchall())


def get_visible_contracts(viewer_id: int | None = None) -> list[dict]:
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


def get_all_contracts() -> list[dict]:
    return _contract_select()


def get_user_contracts(user_id: int) -> list[dict]:
    return _contract_select(
        "WHERE c.id_proponente=%s OR c.id_aceitante=%s",
        (user_id, user_id),
    )


def get_profile_contracts(profile_user_id: int, viewer_id: int | None = None) -> list[dict]:
    if viewer_id == profile_user_id:
        return get_user_contracts(profile_user_id)

    if viewer_id:
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

    return _contract_select(
        """
        WHERE (c.id_proponente=%s OR c.id_aceitante=%s)
          AND c.visibilidade='publico'
          AND c.estado IN ('assinado','sanado')
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
    # A trigger atualiza o estado para 'assinado' quando ambas as assinaturas existem.
    with get_db() as conn:
        conn.cursor().callproc("sp_save_signature", (contract_id, user_id, signature))


def mark_sanado(contract_id: int, user_id: int) -> None:
    with get_db() as conn:
        conn.cursor().callproc("sp_mark_sanado", (contract_id, user_id))


def mark_rejeitado(contract_id: int, user_id: int) -> None:
    with get_db() as conn:
        conn.cursor().callproc("sp_mark_rejeitado", (contract_id, user_id))


def update_contract_text_for_demo(contract_id: int, new_text: str) -> None:
    """Usado apenas para a demonstração de ataque/tampering."""

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE contratos SET texto_contrato=%s WHERE id=%s",
            (new_text, contract_id),
        )


# ---------------------------------------------------------------------------
# Auditoria e segurança
# ---------------------------------------------------------------------------

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
        conn.cursor().callproc(
            "sp_add_audit_log",
            (
                user_id,
                email,
                action,
                contract_id,
                success,
                details,
                ip_address,
                (user_agent or "")[:255],
            ),
        )


def count_recent_failed_logins(email: str, ip_address: str | None, window_minutes: int = 5) -> int:
    window_minutes = max(1, min(int(window_minutes), 1440))
    with get_db() as conn:
        cur = conn.cursor()
        cur.callproc("sp_count_recent_failed_logins", (email, ip_address, window_minutes))
        row = cur.fetchone()
        return int(row["total"] if row else 0)


def get_user_audit_logs(user_id: int, limit: int = 50) -> list[dict]:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT *
            FROM audit_log
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
        cur.execute(
            """
            SELECT logins, failures, openssl_exports
            FROM v_user_security_stats
            WHERE id_utilizador=%s
            """,
            (user_id,),
        )
        row = cur.fetchone()

    if not row:
        return {"logins": 0, "failures": 0, "openssl_exports": 0}

    return {
        "logins": int(row["logins"] or 0),
        "failures": int(row["failures"] or 0),
        "openssl_exports": int(row["openssl_exports"] or 0),
    }
