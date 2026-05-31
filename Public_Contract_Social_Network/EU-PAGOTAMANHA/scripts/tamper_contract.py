from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import database as db  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Altera o texto de um contrato para demonstrar que a assinatura deixa de ser válida.")
    parser.add_argument("contract_id", type=int, help="ID do contrato a alterar")
    parser.add_argument("new_text", help="Novo texto a gravar em texto_contrato")
    args = parser.parse_args()

    contract = db.get_contract(args.contract_id)
    if not contract:
        print(f"Contrato #{args.contract_id} não encontrado.")
        return 1

    print("ANTES:")
    print(contract["texto_contrato"])
    db.update_contract_text_for_demo(args.contract_id, args.new_text)
    print("\nDEPOIS:")
    print(args.new_text)
    print("\nAbre /contracts/{}/verify: a assinatura deve passar a inválida.".format(args.contract_id))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
