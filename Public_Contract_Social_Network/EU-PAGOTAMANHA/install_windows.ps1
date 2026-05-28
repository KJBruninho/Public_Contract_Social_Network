param(
    [string]$MysqlHost = "127.0.0.1",
    [string]$MysqlPort = "3306",
    [string]$MysqlDatabase = "EUPagoAmanhaDB",
    [string]$MysqlUser = "root",
    [string]$MysqlPassword = "password",
    [switch]$ResetDatabase
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "======================================="
Write-Host " EU-PAGOTAMANHA - Windows Installer"
Write-Host "======================================="
Write-Host ""

# Ensure script is being run from the project folder
if (!(Test-Path ".\requirements.txt")) {
    Write-Host "ERRO: requirements.txt nao encontrado."
    Write-Host "Executa este script dentro da pasta EU-PAGOTAMANHA."
    exit 1
}

if (!(Test-Path ".\app.py")) {
    Write-Host "ERRO: app.py nao encontrado."
    Write-Host "Executa este script dentro da pasta EU-PAGOTAMANHA."
    exit 1
}

# Create virtual environment
if (!(Test-Path ".\.venv")) {
    Write-Host "A criar ambiente virtual..."
    py -3 -m venv .venv
} else {
    Write-Host "Ambiente virtual ja existe. A reutilizar .venv."
}

# Activate venv for this process
$activate = ".\.venv\Scripts\Activate.ps1"
if (!(Test-Path $activate)) {
    Write-Host "ERRO: Activate.ps1 nao encontrado. A .venv pode estar corrompida."
    Write-Host "Apaga .venv e volta a correr o script."
    exit 1
}

Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
. $activate

Write-Host "Python em uso:"
python -c "import sys; print(sys.executable)"

# Install dependencies
Write-Host "A atualizar pip..."
python -m pip install --upgrade pip

Write-Host "A instalar dependencias..."
python -m pip install -r requirements.txt

# Create .env
$secret = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 64 | ForEach-Object {[char]$_})

$envContent = @"
MYSQL_HOST=$MysqlHost
MYSQL_PORT=$MysqlPort
MYSQL_DATABASE=$MysqlDatabase
MYSQL_USERNAME=$MysqlUser
MYSQL_PASSWORD=$MysqlPassword

FLASK_SECRET_KEY=$secret
FLASK_ENV=development
BIND_HOST=127.0.0.1
ALLOWED_HOSTS=localhost,127.0.0.1
TRUST_PROXY=0

RECAPTCHA_SITE_KEY=
RECAPTCHA_SECRET_KEY=
"@

if (Test-Path ".\.env") {
    Write-Host ".env ja existe."
    $answer = Read-Host "Queres substituir o .env existente? (s/N)"
    if ($answer -eq "s" -or $answer -eq "S") {
        $envContent | Out-File -FilePath ".\.env" -Encoding utf8
        Write-Host ".env substituido."
    } else {
        Write-Host ".env mantido."
    }
} else {
    $envContent | Out-File -FilePath ".\.env" -Encoding utf8
    Write-Host ".env criado."
}

# Test DB connection
Write-Host ""
Write-Host "A testar ligacao a base de dados..."
python test_db_connection.py

# Optional reset and seed
if ($ResetDatabase) {
    Write-Host ""
    Write-Host "A recriar e popular a base de dados..."
    python scripts\reset_and_seed.py
} else {
    Write-Host ""
    $seed = Read-Host "Queres recriar/popular a BD agora? Isto pode apagar dados existentes. (s/N)"
    if ($seed -eq "s" -or $seed -eq "S") {
        python scripts\reset_and_seed.py
    } else {
        Write-Host "Seed ignorado."
    }
}

Write-Host ""
Write-Host "Instalacao concluida."
Write-Host "Para correr a app:"
Write-Host "  .\.venv\Scripts\Activate.ps1"
Write-Host "  python app.py"
Write-Host ""
Write-Host "URL:"
Write-Host "  http://127.0.0.1:5000"
Write-Host ""
