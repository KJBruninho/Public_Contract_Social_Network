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
    cur.execute(
        """
        SELECT COUNT(*) AS total
        FROM information_schema.statistics
        WHERE table_schema=%s AND table_name=%s AND index_name=%s
        """,
        (DB_NAME, table, index_name),
    )
    if cur.fetchone()["total"] == 0:
        cur.execute(ddl)


def _ensure_db_views(cur) -> None:
    """Creates database views used by the app.

    Views keep repeated SELECT/JOIN logic in MySQL while the Python layer keeps
    authentication, authorization and cryptography.
    """
    cur.execute("""
        CREATE OR REPLACE VIEW v_contratos_com_partes AS
        SELECT
            c.*,
            p.nome AS proponente_nome,
            p.email AS proponente_email,
            a.nome AS aceitante_nome,
            a.email AS aceitante_email,
            (
                SELECT COUNT(*)
                FROM assinaturas_contrato s
                WHERE s.id_contrato = c.id
                  AND s.assinatura_digital IS NOT NULL
            ) AS assinaturas_count
        FROM contratos c
        JOIN utilizadores p ON p.id = c.id_proponente
        JOIN utilizadores a ON a.id = c.id_aceitante
    """)

    cur.execute("""
        CREATE OR REPLACE VIEW v_contratos_publicos AS
        SELECT *
        FROM v_contratos_com_partes
        WHERE visibilidade = 'publico'
          AND estado IN ('assinado', 'sanado')
    """)

    cur.execute("""
        CREATE OR REPLACE VIEW v_user_security_stats AS
        SELECT
            u.id AS id_utilizador,
            COUNT(CASE WHEN l.acao = 'LOGIN_OK' THEN 1 END) AS logins,
            COUNT(CASE WHEN l.sucesso = FALSE THEN 1 END) AS failures,
            COUNT(CASE WHEN l.acao = 'CONTRACT_EXPORTED_OPENSSL_ZIP' THEN 1 END) AS openssl_exports
        FROM utilizadores u
        LEFT JOIN audit_log l ON l.id_utilizador = u.id
        GROUP BY u.id
    """)


def _ensure_db_triggers(cur) -> None:
    """Creates DB-level integrity triggers.

    These triggers enforce simple contract invariants and state transitions.
    They deliberately do not perform cryptography.
    """
    for trigger_name in (
        "trg_contrato_no_self_contract_bi",
        "trg_contrato_no_self_contract_bu",
        "trg_contrato_reveal_at_check_bi",
        "trg_contrato_reveal_at_check_bu",
        "trg_assinatura_after_insert",
        "trg_assinatura_after_update",
    ):
        cur.execute(f"DROP TRIGGER IF EXISTS `{trigger_name}`")

    cur.execute("""
        CREATE TRIGGER trg_contrato_no_self_contract_bi
        BEFORE INSERT ON contratos
        FOR EACH ROW
        BEGIN
            IF NEW.id_proponente = NEW.id_aceitante THEN
                SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Proponente e aceitante não podem ser o mesmo utilizador';
            END IF;
        END
    """)

    cur.execute("""
        CREATE TRIGGER trg_contrato_no_self_contract_bu
        BEFORE UPDATE ON contratos
        FOR EACH ROW
        BEGIN
            IF NEW.id_proponente = NEW.id_aceitante THEN
                SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Proponente e aceitante não podem ser o mesmo utilizador';
            END IF;
        END
    """)

    cur.execute("""
        CREATE TRIGGER trg_contrato_reveal_at_check_bi
        BEFORE INSERT ON contratos
        FOR EACH ROW
        BEGIN
            IF NEW.encrypted_text IS NOT NULL AND NEW.reveal_at IS NULL THEN
                SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Contrato cifrado precisa de reveal_at';
            END IF;
        END
    """)

    cur.execute("""
        CREATE TRIGGER trg_contrato_reveal_at_check_bu
        BEFORE UPDATE ON contratos
        FOR EACH ROW
        BEGIN
            IF NEW.encrypted_text IS NOT NULL AND NEW.reveal_at IS NULL THEN
                SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Contrato cifrado precisa de reveal_at';
            END IF;
        END
    """)

    cur.execute("""
        CREATE TRIGGER trg_assinatura_after_insert
        AFTER INSERT ON assinaturas_contrato
        FOR EACH ROW
        BEGIN
            IF NEW.assinatura_digital IS NOT NULL THEN
                UPDATE contratos
                SET estado = 'assinado'
                WHERE id = NEW.id_contrato
                  AND estado = 'pendente'
                  AND (
                      SELECT COUNT(*)
                      FROM assinaturas_contrato
                      WHERE id_contrato = NEW.id_contrato
                        AND assinatura_digital IS NOT NULL
                  ) >= 2;
            END IF;
        END
    """)

    cur.execute("""
        CREATE TRIGGER trg_assinatura_after_update
        AFTER UPDATE ON assinaturas_contrato
        FOR EACH ROW
        BEGIN
            IF NEW.assinatura_digital IS NOT NULL THEN
                UPDATE contratos
                SET estado = 'assinado'
                WHERE id = NEW.id_contrato
                  AND estado = 'pendente'
                  AND (
                      SELECT COUNT(*)
                      FROM assinaturas_contrato
                      WHERE id_contrato = NEW.id_contrato
                        AND assinatura_digital IS NOT NULL
                  ) >= 2;
            END IF;
        END
    """)


def _ensure_db_procedures(cur) -> None:
    """Creates stored procedures for transactional DB operations."""
    for procedure_name in (
        "sp_save_signature",
        "sp_mark_sanado",
        "sp_mark_rejeitado",
        "sp_add_audit_log",
    ):
        cur.execute(f"DROP PROCEDURE IF EXISTS `{procedure_name}`")

    cur.execute("""
        CREATE PROCEDURE sp_save_signature(
            IN p_contract_id INT,
            IN p_user_id INT,
            IN p_signature LONGTEXT
        )
        BEGIN
            UPDATE assinaturas_contrato
            SET assinatura_digital = p_signature,
                data_assinatura = NOW()
            WHERE id_contrato = p_contract_id
              AND id_utilizador = p_user_id
              AND assinatura_digital IS NULL;

            IF ROW_COUNT() = 0 THEN
                SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Assinatura inexistente, duplicada ou utilizador inválido';
            END IF;
        END
    """)

    cur.execute("""
        CREATE PROCEDURE sp_mark_sanado(
            IN p_contract_id INT,
            IN p_user_id INT
        )
        BEGIN
            UPDATE contratos
            SET estado = 'sanado'
            WHERE id = p_contract_id
              AND id_aceitante = p_user_id
              AND estado = 'assinado';

            IF ROW_COUNT() = 0 THEN
                SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Só o aceitante pode marcar contrato assinado como sanado';
            END IF;
        END
    """)

    cur.execute("""
        CREATE PROCEDURE sp_mark_rejeitado(
            IN p_contract_id INT,
            IN p_user_id INT
        )
        BEGIN
            UPDATE contratos
            SET estado = 'rejeitado'
            WHERE id = p_contract_id
              AND estado = 'pendente'
              AND (id_proponente = p_user_id OR id_aceitante = p_user_id);

            IF ROW_COUNT() = 0 THEN
                SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Só uma parte pode rejeitar contrato pendente';
            END IF;
        END
    """)

    cur.execute("""
        CREATE PROCEDURE sp_add_audit_log(
            IN p_user_id INT,
            IN p_email VARCHAR(180),
            IN p_action VARCHAR(80),
            IN p_contract_id INT,
            IN p_success BOOLEAN,
            IN p_details TEXT,
            IN p_ip VARCHAR(64),
            IN p_user_agent VARCHAR(255)
        )
        BEGIN
            INSERT INTO audit_log
            (id_utilizador, email, acao, id_contrato, sucesso, detalhes, ip_address, user_agent)
            VALUES
            (p_user_id, p_email, p_action, p_contract_id, p_success, p_details, p_ip, LEFT(COALESCE(p_user_agent, ''), 255));
        END
    """)


def _ensure_db_routines(cur) -> None:
    _ensure_db_views(cur)
    _ensure_db_triggers(cur)
    _ensure_db_procedures(cur)


def init_db() -> None:
    """Valida que a base de dados já foi criada pelos scripts SQL."""

    required_tables = [
        "utilizadores",
        "chaves_utilizador",
        "contratos",
        "assinaturas_contrato",
        "password_history",
        "audit_log",
    ]

    required_views = [
        "v_contratos_com_partes",
        "v_contratos_publicos",
        "v_user_security_stats",
    ]

    required_procedures = [
        "sp_save_signature",
        "sp_mark_sanado",
        "sp_mark_rejeitado",
        "sp_add_audit_log",
    ]

    with get_db() as conn:
        cur = conn.cursor()

        for table in required_tables:
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
                    "Executa scripts/reset_and_seed.py antes de arrancar a app."
                )

        for view in required_views:
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
                    "Executa scripts/db_routines.sql ou scripts/reset_and_seed.py."
                )

        for procedure in required_procedures:
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
                    "Executa scripts/db_routines.sql ou scripts/reset_and_seed.py."
                )

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
    """Saves a signature through a stored procedure.

    The trigger trg_assinatura_after_update changes the contract state to
    'assinado' when both signatures exist.
    """
    with get_db() as conn:
        conn.cursor().callproc("sp_save_signature", (contract_id, user_id, signature))


def mark_sanado(contract_id: int, user_id: int | None = None) -> None:
    """Marks a contract as settled.

    If user_id is supplied, the DB procedure enforces that the user is the
    aceitante. Without user_id, this keeps backward compatibility with older
    app.py versions that already check permissions before calling this function.
    """
    with get_db() as conn:
        cur = conn.cursor()
        if user_id is None:
            cur.execute("UPDATE contratos SET estado='sanado' WHERE id=%s", (contract_id,))
        else:
            cur.callproc("sp_mark_sanado", (contract_id, user_id))


def mark_rejeitado(contract_id: int, user_id: int | None = None) -> None:
    """Rejects a pending contract.

    If user_id is supplied, the DB procedure enforces that the user is one of
    the two parties. Without user_id, this keeps compatibility with old app.py.
    """
    with get_db() as conn:
        cur = conn.cursor()
        if user_id is None:
            cur.execute("UPDATE contratos SET estado='rejeitado' WHERE id=%s AND estado='pendente'", (contract_id,))
        else:
            cur.callproc("sp_mark_rejeitado", (contract_id, user_id))


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


def update_contract_text_for_demo(contract_id: int, new_text: str) -> None:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE contratos SET texto_contrato=%s WHERE id=%s", (new_text, contract_id))


def seed_basic() -> None:
    # Used by scripts/reset_and_seed.py; kept here for convenience.
    pass
