@echo off
setlocal

echo.
echo =======================================
echo  EU-PAGOTAMANHA - Windows Installer
echo =======================================
echo.

if not exist requirements.txt (
    echo ERRO: requirements.txt nao encontrado.
    echo Executa este ficheiro dentro da pasta EU-PAGOTAMANHA.
    exit /b 1
)

if not exist app.py (
    echo ERRO: app.py nao encontrado.
    echo Executa este ficheiro dentro da pasta EU-PAGOTAMANHA.
    exit /b 1
)

if not exist .venv (
    echo A criar ambiente virtual...
    py -3 -m venv .venv
) else (
    echo Ambiente virtual ja existe. A reutilizar .venv.
)

call .venv\Scripts\activate.bat

echo A atualizar pip...
python -m pip install --upgrade pip

echo A instalar dependencias...
python -m pip install -r requirements.txt

if not exist .env (
    echo A criar .env...
    copy .env.example .env
    echo.
    echo IMPORTANTE: edita o ficheiro .env com a password correta do MariaDB/MySQL.
) else (
    echo .env ja existe. Mantido.
)

echo.
echo A testar ligacao a BD...
python test_db_connection.py

echo.
set /p seed="Queres recriar/popular a BD agora? Isto pode apagar dados existentes. (s/N): "
if /I "%seed%"=="s" (
    python scripts\reset_and_seed.py
) else (
    echo Seed ignorado.
)

echo.
echo Instalacao concluida.
echo Para correr:
echo   .venv\Scripts\activate.bat
echo   python app.py
echo.
echo URL: http://127.0.0.1:5000
echo.

endlocal
