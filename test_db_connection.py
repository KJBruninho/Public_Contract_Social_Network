import database as db

try:
    db.init_db()
    with db.get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT DATABASE() AS db_name")
            print("Ligação OK:", cur.fetchone()["db_name"])
except Exception as exc:
    print("Erro na ligação à BD:", exc)
    raise
