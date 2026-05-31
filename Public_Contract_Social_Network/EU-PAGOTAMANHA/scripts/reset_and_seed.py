from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import pymysql
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash


SCRIPT_PATH = Path(__file__).resolve()

# Suporta o ficheiro tanto em:
#   EU-PAGOTAMANHA/reset_and_seed.py
# como em:
#   EU-PAGOTAMANHA/scripts/reset_and_seed.py
if (SCRIPT_PATH.parent / "app.py").exists():
    ROOT = SCRIPT_PATH.parent
else:
    ROOT = SCRIPT_PATH.parents[1]

sys.path.insert(0, str(ROOT))

import crypto_utils as crypto  # noqa: E402


load_dotenv(ROOT / ".env")

MYSQL_HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3306"))
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "EUPagoAmanhaDB")
MYSQL_USERNAME = os.getenv("MYSQL_USERNAME", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")

DEMO_PASSWORD = "password"


def find_sql_file(filename: str) -> Path:
    candidates = [
        ROOT / filename,
        ROOT / "sql" / filename,
        ROOT / "scripts" / filename,
        ROOT / "scripts" / "BD_sql_Querys" / filename,
    ]

    for path in candidates:
        if path.exists():
            return path

    searched = "\n".join(f"  - {p}" for p in candidates)
    raise FileNotFoundError(f"Não encontrei {filename}. Procurei em:\n{searched}")


def split_sql(sql: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []

    in_single = False
    in_double = False
    escape = False
    i = 0

    while i < len(sql):
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < len(sql) else ""

        if not in_single and not in_double and ch == "-" and nxt == "-":
            while i < len(sql) and sql[i] not in "\r\n":
                i += 1
            continue

        if not in_single and not in_double and ch == "#":
            while i < len(sql) and sql[i] not in "\r\n":
                i += 1
            continue

        if ch == "\\" and not escape:
            escape = True
            current.append(ch)
            i += 1
            continue

        if ch == "'" and not escape and not in_double:
            in_single = not in_single
        elif ch == '"' and not escape and not in_single:
            in_double = not in_double

        if ch == ";" and not in_single and not in_double:
            statement = "".join(current).strip()
            if statement:
                statements.append(statement)
            current = []
        else:
            current.append(ch)

        escape = False
        i += 1

    statement = "".join(current).strip()
    if statement:
        statements.append(statement)

    return statements


def connect(database: str | None = None):
    kwargs = {
        "host": MYSQL_HOST,
        "port": MYSQL_PORT,
        "user": MYSQL_USERNAME,
        "password": MYSQL_PASSWORD,
        "charset": "utf8mb4",
        "autocommit": True,
        "cursorclass": pymysql.cursors.DictCursor,
    }

    if database:
        kwargs["database"] = database

    return pymysql.connect(**kwargs)


def execute_sql_file(path: Path) -> None:
    print(f"A executar {path.name}...")
    sql = path.read_text(encoding="utf-8")
    statements = split_sql(sql)

    conn = connect(None)
    try:
        with conn.cursor() as cur:
            for idx, statement in enumerate(statements, start=1):
                try:
                    cur.execute(statement)
                except Exception as exc:
                    print("")
                    print(f"Erro no statement {idx} de {path.name}:")
                    print(statement[:1000])
                    print("")
                    raise exc
    finally:
        conn.close()

    print(f"{path.name} executado com sucesso. Statements: {len(statements)}")


def table_exists(cur, table_name: str) -> bool:
    cur.execute(
        """
        SELECT COUNT(*) AS total
        FROM information_schema.tables
        WHERE table_schema=%s AND table_name=%s
        """,
        (MYSQL_DATABASE, table_name),
    )
    return bool(cur.fetchone()["total"])


def column_exists(cur, table_name: str, column_name: str) -> bool:
    cur.execute(
        """
        SELECT COUNT(*) AS total
        FROM information_schema.columns
        WHERE table_schema=%s AND table_name=%s AND column_name=%s
        """,
        (MYSQL_DATABASE, table_name, column_name),
    )
    return bool(cur.fetchone()["total"])


def ensure_optional_columns(cur) -> None:
    """Garante colunas usadas pelas versões mais recentes da app."""

    optional_columns = [
        ("utilizadores", "mfa_enabled", "BOOLEAN NOT NULL DEFAULT FALSE"),
        ("utilizadores", "mfa_secret", "VARCHAR(255) NULL"),
        ("utilizadores", "password_changed_at", "DATETIME NULL"),
        ("utilizadores", "must_change_password", "BOOLEAN NOT NULL DEFAULT FALSE"),
    ]

    for table, column, definition in optional_columns:
        if table_exists(cur, table) and not column_exists(cur, table, column):
            print(f"A adicionar coluna {table}.{column}...")
            cur.execute(f"ALTER TABLE `{table}` ADD COLUMN `{column}` {definition}")


def fix_demo_users_and_keys() -> None:
    """Corrige password_hash e chaves privadas dos utilizadores seed.

    O erro anterior era atualizar só password_hash.
    Isso deixava a password de login válida, mas a chave privada continuava
    cifrada com outra password.

    Esta função:
    - define a password demo como 'password';
    - gera novo par RSA para cada utilizador;
    - cifra a nova chave privada com 'password';
    - atualiza a chave pública;
    - re-assina assinaturas existentes para não ficarem inválidas.
    """

    print("A corrigir utilizadores demo, passwords e chaves RSA...")

    conn = connect(MYSQL_DATABASE)
    private_keys_by_user_id: dict[int, str] = {}

    try:
        with conn.cursor() as cur:
            ensure_optional_columns(cur)

            cur.execute("SELECT id, email FROM utilizadores ORDER BY id")
            users = list(cur.fetchall())

            if not users:
                print("Não há utilizadores para corrigir.")
                return

            password_hash = generate_password_hash(DEMO_PASSWORD, method="scrypt", salt_length=16)

            for user in users:
                user_id = int(user["id"])
                email = user["email"]

                private_pem, public_pem = crypto.generate_rsa_keypair()
                encrypted = crypto.encrypt_private_key(private_pem, DEMO_PASSWORD)
                private_keys_by_user_id[user_id] = private_pem

                # Atualiza password. Também desativa MFA para não bloquear contas demo.
                update_fields = ["password_hash=%s"]
                params: list[object] = [password_hash]

                if column_exists(cur, "utilizadores", "password_changed_at"):
                    update_fields.append("password_changed_at=NOW()")
                if column_exists(cur, "utilizadores", "must_change_password"):
                    update_fields.append("must_change_password=FALSE")
                if column_exists(cur, "utilizadores", "mfa_enabled"):
                    update_fields.append("mfa_enabled=FALSE")
                if column_exists(cur, "utilizadores", "mfa_secret"):
                    update_fields.append("mfa_secret=NULL")

                params.append(user_id)

                cur.execute(
                    f"""
                    UPDATE utilizadores
                    SET {", ".join(update_fields)}
                    WHERE id=%s
                    """,
                    tuple(params),
                )

                # Atualiza ou cria chaves do utilizador.
                cur.execute(
                    "SELECT id FROM chaves_utilizador WHERE id_utilizador=%s",
                    (user_id,),
                )
                existing_key = cur.fetchone()

                if existing_key:
                    cur.execute(
                        """
                        UPDATE chaves_utilizador
                        SET public_key=%s,
                            encrypted_private_key=%s,
                            private_key_salt=%s,
                            private_key_iv=%s,
                            private_key_algorithm=%s
                        WHERE id_utilizador=%s
                        """,
                        (
                            public_pem,
                            encrypted["encrypted_private_key"],
                            encrypted["private_key_salt"],
                            encrypted["private_key_iv"],
                            encrypted.get("private_key_algorithm", "AES-256-CBC"),
                            user_id,
                        ),
                    )
                else:
                    cur.execute(
                        """
                        INSERT INTO chaves_utilizador
                        (id_utilizador, public_key, encrypted_private_key,
                         private_key_salt, private_key_iv, private_key_algorithm)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        (
                            user_id,
                            public_pem,
                            encrypted["encrypted_private_key"],
                            encrypted["private_key_salt"],
                            encrypted["private_key_iv"],
                            encrypted.get("private_key_algorithm", "AES-256-CBC"),
                        ),
                    )

                print(f"  - {email} / {DEMO_PASSWORD}: password e chave RSA corrigidas")

            if table_exists(cur, "password_history"):
                cur.execute("DELETE FROM password_history")
                for user in users:
                    cur.execute(
                        """
                        INSERT INTO password_history (id_utilizador, password_hash)
                        VALUES (%s, %s)
                        """,
                        (user["id"], password_hash),
                    )

            resign_existing_signatures(cur, private_keys_by_user_id)

    finally:
        conn.close()

    print("Utilizadores demo corrigidos.")


def resign_existing_signatures(cur, private_keys_by_user_id: dict[int, str]) -> None:
    """Reassina assinaturas existentes depois de regenerar as chaves RSA."""

    if not table_exists(cur, "contratos") or not table_exists(cur, "assinaturas_contrato"):
        return

    print("A re-assinar assinaturas existentes...")

    cur.execute(
        """
        SELECT
            s.id AS signature_id,
            s.id_utilizador,
            c.id AS contract_id,
            c.id_proponente,
            c.id_aceitante,
            c.texto_contrato,
            c.data_criacao
        FROM assinaturas_contrato s
        JOIN contratos c ON c.id = s.id_contrato
        WHERE s.assinatura_digital IS NOT NULL
        """
    )

    rows = list(cur.fetchall())
    total = 0

    for row in rows:
        user_id = int(row["id_utilizador"])
        private_pem = private_keys_by_user_id.get(user_id)

        if not private_pem:
            continue

        payload = crypto.canonical_contract_payload(row)
        signature = crypto.sign_payload(private_pem, payload)

        cur.execute(
            """
            UPDATE assinaturas_contrato
            SET assinatura_digital=%s
            WHERE id=%s
            """,
            (signature, row["signature_id"]),
        )
        total += 1

    print(f"Assinaturas re-assinadas: {total}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reset e seed da BD EU-PAGOTAMANHÃ usando init.sql + populate.sql."
    )
    parser.add_argument("--no-populate", action="store_true", help="Executa só init.sql.")
    parser.add_argument(
        "--no-fix-passwords",
        action="store_true",
        help="Não corrige passwords/chaves demo para 'password'.",
    )
    args = parser.parse_args()

    print("=======================================")
    print(" EU-PAGOTAMANHÃ - reset_and_seed")
    print("=======================================")
    print(f"Root: {ROOT}")
    print(f"Host: {MYSQL_HOST}:{MYSQL_PORT}")
    print(f"Database: {MYSQL_DATABASE}")
    print(f"User: {MYSQL_USERNAME}")
    print("")

    init_sql = find_sql_file("init.sql")
    execute_sql_file(init_sql)

    if not args.no_populate:
        populate_sql = find_sql_file("populate.sql")
        execute_sql_file(populate_sql)

        if not args.no_fix_passwords:
            fix_demo_users_and_keys()

    print("")
    print("Base de dados pronta.")
    print("")
    print("Credenciais demo:")
    print("  ana@example.com      / password")
    print("  bruno@example.com    / password")
    print("  carla@example.com    / password")
    print("  diogo@example.com    / password")
    print("")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())