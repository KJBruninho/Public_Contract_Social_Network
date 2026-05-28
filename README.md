# EU-PAGOTAMANHÃ

**EU-PAGOTAMANHÃ** é uma aplicação web desenvolvida em Flask para criação, assinatura e publicação de contratos digitais entre utilizadores registados.

O projeto simula uma rede social de contratos: os utilizadores registam-se, recebem um par de chaves criptográficas, criam contratos com outros utilizadores, assinam digitalmente esses contratos e disponibilizam-nos para consulta/verificação pública.

Projeto desenvolvido no contexto da unidade curricular de **Segurança Informática & Cibersegurança**.

---

## Funcionalidades

### Utilizadores

- Registo com nome, e-mail e palavra-passe.
- Login/logout com sessões Flask.
- Geração de par de chaves RSA no registo.
- Armazenamento da chave pública.
- Armazenamento da chave privada cifrada.
- Perfil público de utilizador com chave pública visível.

### Contratos

- Criação de contratos entre dois utilizadores.
- Texto livre para o conteúdo do contrato.
- Estados de contrato:
  - pendente;
  - assinado parcialmente;
  - assinado por ambas as partes;
  - público;
  - sanado/concluído.
- Listagem pública de contratos.
- Dashboard privado para utilizadores autenticados.
- Página de detalhe do contrato.

### Segurança

- Assinaturas digitais com RSA.
- Verificação de assinaturas digitais.
- Proteção da chave privada com cifra simétrica.
- Suporte para cifragem de contratos.
- Suporte para algoritmos como:
  - AES-256-CBC;
  - AES-256-CTR;
  - HMAC-SHA256;
  - HMAC-SHA512.
- Validação básica de inputs.
- Separação entre utilizadores autenticados e não autenticados.

### Interface

- Frontend com Flask/Jinja2.
- Layout responsivo.
- Modo claro/escuro.
- Estilo visual tipo SaaS, com cards, dashboard e navegação organizada.

---

## Tecnologias usadas

- Python 3
- Flask
- Jinja2
- MariaDB/MySQL
- PyMySQL
- Cryptography
- Werkzeug
- python-dotenv
- HTML5
- CSS3
- JavaScript

---

## Estrutura do projeto

```text
EU-PAGOTAMANHA/
├── app.py
├── database.py
├── crypto_utils.py
├── requirements.txt
├── env.example
├── test_db_connection.py
│
├── scripts/
│   ├── BD_sql_Querys/
|   │   └── init.sql
|   │   └── populate.sql
│   └── reset_and_seed.py
│
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── dashboard.html
│   ├── contracts.html
│   ├── create_contract.html
│   ├── view_contract.html
│   ├── sign_contract.html
│   ├── verify.html
│   ├── verify_manual.html
│   ├── login.html
│   ├── register.html
│   ├── profile.html
│   ├── users.html
│   └── _contract_card.html
│
└── static/
    ├── css/
    │   └── style.css
    └── js/
        └── main.js
```

---

## Requisitos

Antes de instalar, garante que tens instalado:

- Python 3.11 ou superior;
- MariaDB ou MySQL;
- Git;
- pip;
- ambiente virtual Python.

Para verificar:

```bash
python --version
pip --version
mysql --version
```

---

## Instalação

### 1. Clonar o repositório

```bash
git clone https://github.com/teu-utilizador/EU-PAGOTAMANHA.git
cd EU-PAGOTAMANHA
```

Se o projeto estiver dentro de outro repositório, entra diretamente na pasta da aplicação:

```bash
cd Public_Contract_Social_Network/EU-PAGOTAMANHA
```

---

### 2. Criar ambiente virtual

No Windows PowerShell:

```powershell
py -3 -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

No Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

### 3. Instalar dependências

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

---

### 4. Configurar variáveis de ambiente

Copia o ficheiro de exemplo:

No Windows:

```powershell
copy env.example .env
```

No Linux/macOS:

```bash
cp env.example .env
```

Edita o ficheiro `.env`:

```env
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_DATABASE=EUPagoAmanhaDB
MYSQL_USERNAME=root
MYSQL_PASSWORD=password

FLASK_SECRET_KEY=troca_isto_por_um_valor_seguro
FLASK_ENV=development
```

Altera `MYSQL_USERNAME` e `MYSQL_PASSWORD` de acordo com a tua instalação de MariaDB/MySQL.

---

### 5. Testar ligação à base de dados

```bash
python test_db_connection.py
```

Resultado esperado:

```text
Ligação OK: eupagoamanhadb
```

Se a ligação falhar, confirma:

- se o MariaDB/MySQL está ligado;
- se a password está correta;
- se a porta é `3306`;
- se o `.env` está na pasta certa.

---

### 6. Criar e popular a base de dados

O projeto inclui um script para recriar e popular a base de dados com dados de teste:

```bash
python scripts/reset_and_seed.py
```

Este script cria:

- utilizadores;
- chaves RSA;
- contratos;
- assinaturas;
- dados iniciais para demonstração.

---

### 7. Executar a aplicação

```bash
python app.py
```

A aplicação fica disponível em:

```text
http://127.0.0.1:5000
```

---

## Contas de teste

Depois de correr o script de seed, podes usar:

```text
ana@example.com      password
bruno@example.com    password
carla@example.com    password
diogo@example.com    password
```

---

## Fluxo principal da aplicação

1. Um utilizador regista-se.
2. O sistema gera um par de chaves RSA.
3. A chave pública fica disponível no perfil.
4. A chave privada é guardada cifrada.
5. Um utilizador cria um contrato com outro utilizador.
6. O contrato fica pendente.
7. Cada parte assina digitalmente o contrato.
8. O sistema permite verificar a validade das assinaturas.
9. O contrato pode ficar público para consulta.

---

## Notas sobre segurança

Este projeto é académico/prototípico. Algumas decisões foram tomadas para facilitar a demonstração local.

Pontos implementados ou previstos:

- geração de chaves RSA;
- assinatura digital de contratos;
- verificação de assinaturas;
- armazenamento cifrado da chave privada;
- suporte para contratos cifrados;
- HMAC para autenticação/integridade;
- controlo de sessões.

Pontos a reforçar numa versão de produção:

- gestão robusta de sessões;
- proteção CSRF;
- rate limiting;
- política forte de passwords;
- logs de auditoria;
- rotação de chaves;
- HTTPS obrigatório;
- hardening da base de dados;
- validação e sanitização adicionais;
- proteção contra XSS e SQL injection;
- separação de permissões por perfil.

---

## Possível ataque demonstrável

Um ataque simples para apresentação consiste em alterar o texto de um contrato já assinado.

Resultado esperado:

- a assinatura digital deixa de ser válida;
- o sistema deteta que o conteúdo foi alterado;
- a verificação falha.

Isto demonstra a utilidade das assinaturas digitais para garantir integridade e autenticidade.

---

## Problemas comuns

### `No module named flask`

O ambiente virtual não está ativo ou as dependências não foram instaladas.

Solução:

```bash
python -m pip install -r requirements.txt
```

---

### `Can't connect to MySQL server`

Confirma se o MariaDB/MySQL está ligado e se o `.env` tem:

```env
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
```

---

### `Access denied for user 'root'`

A password no `.env` está errada ou o utilizador não tem permissões.

---

### `Unknown column ...`

A estrutura da base de dados está antiga. Recria a BD:

```bash
python scripts/reset_and_seed.py
```

---

### CSS não atualiza

Força refresh no browser:

```text
Ctrl + F5
```

Ou limpa a cache no painel de Developer Tools.

---

## Licença

Projeto académico. Uso livre para estudo, demonstração e desenvolvimento.

---

## Autor

Desenvolvido por Bruno no âmbito de Segurança Informática & Cibersegurança.
