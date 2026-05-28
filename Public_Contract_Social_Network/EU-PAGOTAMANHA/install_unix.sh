#!/usr/bin/env bash
set -e

MYSQL_HOST="${MYSQL_HOST:-127.0.0.1}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_DATABASE="${MYSQL_DATABASE:-EUPagoAmanhaDB}"
MYSQL_USERNAME="${MYSQL_USERNAME:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-password}"

echo ""
echo "======================================="
echo " EU-PAGOTAMANHA - Linux/macOS Installer"
echo "======================================="
echo ""

if [ ! -f "requirements.txt" ]; then
  echo "ERRO: requirements.txt nao encontrado."
  echo "Executa este script dentro da pasta EU-PAGOTAMANHA."
  exit 1
fi

if [ ! -f "app.py" ]; then
  echo "ERRO: app.py nao encontrado."
  echo "Executa este script dentro da pasta EU-PAGOTAMANHA."
  exit 1
fi

if [ ! -d ".venv" ]; then
  echo "A criar ambiente virtual..."
  python3 -m venv .venv
else
  echo "Ambiente virtual ja existe. A reutilizar .venv."
fi

source .venv/bin/activate

echo "Python em uso:"
python -c "import sys; print(sys.executable)"

echo "A atualizar pip..."
python -m pip install --upgrade pip

echo "A instalar dependencias..."
python -m pip install -r requirements.txt

SECRET="$(python - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)"

if [ -f ".env" ]; then
  echo ".env ja existe. Mantido."
else
  cat > .env <<EOF
MYSQL_HOST=$MYSQL_HOST
MYSQL_PORT=$MYSQL_PORT
MYSQL_DATABASE=$MYSQL_DATABASE
MYSQL_USERNAME=$MYSQL_USERNAME
MYSQL_PASSWORD=$MYSQL_PASSWORD

FLASK_SECRET_KEY=$SECRET
FLASK_ENV=development
BIND_HOST=127.0.0.1
ALLOWED_HOSTS=localhost,127.0.0.1
TRUST_PROXY=0

RECAPTCHA_SITE_KEY=
RECAPTCHA_SECRET_KEY=
EOF
  echo ".env criado."
fi

echo ""
echo "A testar ligacao a base de dados..."
python test_db_connection.py

echo ""
read -r -p "Queres recriar/popular a BD agora? Isto pode apagar dados existentes. (s/N): " seed
if [[ "$seed" == "s" || "$seed" == "S" ]]; then
  python scripts/reset_and_seed.py
else
  echo "Seed ignorado."
fi

echo ""
echo "Instalacao concluida."
echo "Para correr:"
echo "  source .venv/bin/activate"
echo "  python app.py"
echo ""
echo "URL: http://127.0.0.1:5000"
echo ""
