from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import pymysql
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash


ROOT = Path(__file__).resolve().parents[1]
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
    """Divide um ficheiro SQL em statements.

    Suporta strings com aspas simples/duplas e ignora comentários simples.
    Não suporta DELIMITER/procedures. Para init.sql/populate.sql normais chega.
    """
    statements: list[str] = []
    current: list[str] = []

    in_single = False
    in_double = False
    escape = False
    i = 0

    while i < len(sql):
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < len(sql) else ""

        # Ignorar comentários de linha quando não estamos dentro de strings.
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


def fix_demo_passwords() -> None:
    """Garante que todos os utilizadores demo conseguem fazer login com password.

    Útil porque alguns populate.sql antigos tinham:
        scrypt:32768:8:1$demo$demo
    que não corresponde a password válida.
    """
    print("A corrigir password_hash dos utilizadores demo para a password 'password'...")
    password_hash = generate_password_hash(DEMO_PASSWORD, method="scrypt", salt_length=16)

    conn = connect(MYSQL_DATABASE)
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE utilizadores SET password_hash=%s", (password_hash,))

            # Esta tabela pode não existir em versões antigas.
            try:
                cur.execute("UPDATE password_history SET password_hash=%s", (password_hash,))
            except Exception:
                pass
    finally:
        conn.close()

    print("Passwords demo corrigidas.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Reset e seed da BD EU-PAGOTAMANHÃ usando init.sql + populate.sql.")
    parser.add_argument("--no-populate", action="store_true", help="Executa só init.sql.")
    parser.add_argument("--no-fix-passwords", action="store_true", help="Não corrige passwords demo para 'password'.")
    args = parser.parse_args()

    print("=======================================")
    print(" EU-PAGOTAMANHÃ - reset_and_seed")
    print("=======================================")
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
            fix_demo_passwords()

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
