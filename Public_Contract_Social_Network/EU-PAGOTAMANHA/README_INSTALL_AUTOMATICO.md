## Instalação automática

Além da instalação manual, o projeto inclui scripts para automatizar a criação da `.venv`, instalação das dependências, criação do `.env`, teste da ligação à base de dados e seed inicial.

### Windows PowerShell

Dentro da pasta `EU-PAGOTAMANHA`:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\install_windows.ps1
```

Também podes passar os dados da BD diretamente:

```powershell
.\install_windows.ps1 `
  -MysqlHost "127.0.0.1" `
  -MysqlPort "3306" `
  -MysqlDatabase "EUPagoAmanhaDB" `
  -MysqlUser "root" `
  -MysqlPassword "password" `
  -ResetDatabase
```

### Windows CMD

```bat
install_windows.bat
```

### Linux/macOS

```bash
chmod +x install_unix.sh
./install_unix.sh
```

Com variáveis personalizadas:

```bash
MYSQL_HOST=127.0.0.1 \
MYSQL_PORT=3306 \
MYSQL_DATABASE=EUPagoAmanhaDB \
MYSQL_USERNAME=root \
MYSQL_PASSWORD=password \
./install_unix.sh
```

Depois da instalação:

```bash
python app.py
```

A aplicação fica em:

```text
http://127.0.0.1:5000
```
