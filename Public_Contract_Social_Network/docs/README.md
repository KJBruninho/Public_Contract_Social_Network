# EU-PAGOTAMANHÃ

**EU-PAGOTAMANHÃ** é uma aplicação web desenvolvida em Flask para criação, assinatura, publicação e verificação de contratos digitais entre utilizadores registados.

O projeto simula um livro razão público de contratos: os utilizadores registam-se, recebem um par de chaves RSA, criam contratos com outros utilizadores, assinam digitalmente esses contratos e disponibilizam-nos para consulta/verificação pública.

Projeto desenvolvido no contexto da unidade curricular de **Segurança Informática & Cibersegurança**.

---

## Funcionalidades

### Utilizadores e autenticação

* Registo com nome, e-mail e palavra-passe.
* Login/logout com sessões Flask.
* MFA/TOTP opcional com QR code para aplicações autenticadoras.
* Proteção contra tentativas repetidas de login falhado.
* Alteração de password com histórico de passwords anteriores.
* Expiração/obrigação de alteração de password quando aplicável.
* Dashboard privado para utilizadores autenticados.
* Perfil público com chave pública visível.

### Chaves criptográficas

* Geração automática de par de chaves RSA no registo.
* Chave pública visível no perfil do utilizador.
* Chave privada guardada no sistema cifrada com derivação da password.
* A chave privada não é mostrada na interface ao utilizador.
* Possibilidade de exportação/gestão controlada de material necessário à verificação.

### Contratos

* Criação de contratos entre dois utilizadores registados.
* Texto livre para o conteúdo do contrato.
* Escolha do aceitante.
* Visibilidade pública ou privada.
* Contratos pendentes, assinados, sanados ou rejeitados.
* Assinatura digital pelo proponente.
* Assinatura digital pelo aceitante.
* Rejeição de contratos pendentes.
* Marcação de contrato como sanado pelo aceitante.
* Listagem pública de contratos assinados/sanados.
* Listagem privada dos contratos do utilizador autenticado.
* Página de detalhe do contrato.

### Contratos cifrados

* Possibilidade de cifrar temporariamente o texto público do contrato.
* Criptograma permanece visível publicamente.
* Texto claro só fica visível publicamente depois de `reveal_at`.
* As partes do contrato conseguem ler o texto necessário para assinar.
* Suporte para:

  * AES-256-CBC;
  * AES-256-CTR;
  * HMAC-SHA256;
  * HMAC-SHA512.

### Verificação e exportação

* Verificação interna das assinaturas digitais.
* Verificação manual através de payload, assinatura e chave pública.
* Exportação CSV do contrato.
* Exportação ZIP para verificação externa com OpenSSL.
* Inclusão do payload canónico usado na assinatura.
* Inclusão das assinaturas e chaves públicas necessárias à verificação.

### Auditoria e segurança

* Registo de eventos em `audit_log`.
* Eventos de login, falhas de login, criação de contratos, assinaturas, rejeições, sanações e exportações.
* CSRF tokens em formulários sensíveis.
* Headers básicos de segurança.
* Controlo de acesso para contratos privados e pendentes.
* Views, triggers e stored procedures na base de dados para reforçar integridade e organização.

### Interface

* Frontend com Flask/Jinja2.
* Layout responsivo.
* Tema claro/escuro.
* Navegação pública e privada.
* Páginas para contratos, utilizadores, verificação, dashboard, MFA e segurança.

---

## Tecnologias usadas

* Python 3.11+
* Flask
* Jinja2
* MariaDB/MySQL
* PyMySQL
* Cryptography
* Werkzeug
* python-dotenv
* qrcode
* Pillow
* HTML5
* CSS3
* JavaScript

---

## Estrutura do projeto

```text
Public_Contract_Social_Network/
└── EU-PAGOTAMANHA/
    ├── app.py
    ├── database.py
    ├── crypto_utils.py
    ├── requirements.txt
    ├── env.example
    ├── test_db_connection.py
    │
    ├── scripts/
    │   ├── reset_and_seed.py
    │   └── BD_sql_Querys/
    │       ├── init.sql
    │       └── populate.sql
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
    │   ├── mfa_setup.html
    │   ├── mfa_verify.html
    │   ├── change_password.html
    │   ├── password_expired.html
    │   ├── security.html
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

* Python 3.11 ou superior;
* MariaDB ou MySQL;
* Git;
* pip;
* ambiente virtual Python.

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
git clone https://github.com/KJBruninho/Public_Contract_Social_Network.git
cd Public_Contract_Social_Network/Public_Contract_Social_Network/EU-PAGOTAMANHA
```

Se a estrutura local for diferente, entra diretamente na pasta `EU-PAGOTAMANHA`.

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
BIND_HOST=127.0.0.1
BIND_PORT=5000
```

Altera `MYSQL_USERNAME` e `MYSQL_PASSWORD` de acordo com a tua instalação de MariaDB/MySQL.

---

### 5. Criar e popular a base de dados

Executa:

```bash
python scripts/reset_and_seed.py
```

Este script recria a base de dados, executa os scripts SQL, popula dados de demonstração e garante que as passwords e chaves privadas dos utilizadores seedados ficam coerentes.

---

### 6. Testar ligação e estrutura da BD

```bash
python test_db_connection.py
```

Resultado esperado:

```text
Ligação e estrutura da BD OK: EUPagoAmanhaDB
```

Se falhar, confirma:

* se MariaDB/MySQL está ligado;
* se as credenciais do `.env` estão corretas;
* se executaste `python scripts/reset_and_seed.py`;
* se estás na pasta correta da aplicação.

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

Depois de correr o script de seed, podes usar as contas criadas no `populate.sql`.

Exemplo habitual:

```text
ana@example.com      password
bruno@example.com    password
carla@example.com    password
diogo@example.com    password
```

As passwords demo são apenas para desenvolvimento/apresentação.

---

## Base de dados

A base de dados é criada pelos scripts SQL e usada pela aplicação através de `database.py`.

### Tabelas principais

* `utilizadores`
* `chaves_utilizador`
* `contratos`
* `assinaturas_contrato`
* `password_history`
* `audit_log`

### Views

* `v_contratos_com_partes`
* `v_contratos_publicos`
* `v_user_security_stats`

### Stored procedures

* `sp_save_signature`
* `sp_mark_sanado`
* `sp_mark_rejeitado`
* `sp_add_audit_log`
* `sp_set_mfa`
* `sp_count_recent_failed_logins`
* `sp_create_contract`

### Triggers

* impedem contratos consigo próprio;
* exigem `reveal_at` em contratos cifrados;
* atualizam automaticamente o estado para `assinado` quando existem duas assinaturas.

A criptografia permanece no Python. A base de dados garante armazenamento, relações, integridade, auditoria e transições simples de estado.

---

## Fluxo principal da aplicação

1. Um utilizador regista-se.
2. O sistema gera automaticamente um par de chaves RSA.
3. A chave pública fica visível no perfil.
4. A chave privada é cifrada e guardada no sistema.
5. O utilizador pode ativar MFA.
6. Um utilizador cria um contrato com outro utilizador.
7. O proponente assina digitalmente o contrato.
8. O contrato fica pendente até decisão do aceitante.
9. O aceitante pode assinar ou rejeitar.
10. Quando ambas as partes assinam, o contrato passa para `assinado`.
11. Contratos públicos assinados/sanados ficam visíveis publicamente.
12. Qualquer utilizador pode verificar assinaturas públicas.
13. O aceitante pode marcar o contrato como `sanado`.

---

## Regras de acesso

### Visitante não autenticado

Pode:

* ver página inicial;
* ver contratos públicos assinados/sanados;
* ver perfis públicos e chaves públicas;
* verificar assinaturas manualmente.

Não pode:

* criar contratos;
* assinar contratos;
* ver contratos privados;
* ver contratos pendentes de terceiros.

### Utilizador autenticado

Pode:

* criar contratos;
* ver os seus contratos;
* assinar contratos onde é parte;
* rejeitar contratos pendentes onde é parte;
* exportar contratos a que tem acesso;
* ativar/desativar MFA;
* alterar password.

### Aceitante

Pode:

* assinar o contrato recebido;
* rejeitar contrato pendente;
* marcar contrato assinado como sanado.

---

## Segurança criptográfica

### Chaves RSA

Cada utilizador recebe um par RSA no registo.

* Chave pública: visível no perfil.
* Chave privada: cifrada e guardada no sistema.
* A chave privada não é apresentada ao utilizador na interface.

### Assinatura digital

Cada contrato é assinado sobre um payload canónico composto por:

```text
id_proponente
id_aceitante
texto_contrato
data_criacao
```

A verificação usa:

* payload canónico;
* assinatura digital;
* chave pública do assinante.

### Cifra temporária

Contratos podem ter texto público cifrado temporariamente. O criptograma fica visível, mas o texto claro só fica publicamente acessível depois de `reveal_at`.

---

## Exportação e verificação externa

O sistema permite exportar dados do contrato para verificação externa.

A exportação para OpenSSL inclui, conforme aplicável:

* payload canónico;
* assinatura do proponente;
* assinatura do aceitante;
* chave pública do proponente;
* chave pública do aceitante;
* instruções/comandos de verificação.

Exemplo conceptual:

```bash
openssl dgst -sha256 -verify public_key.pem -signature signature.bin payload.txt
```

No caso de RSA-PSS, os parâmetros de padding devem corresponder aos usados pela aplicação.

---

## Demonstração de ataque

O ataque escolhido para demonstração consiste em adulterar diretamente na base de dados o texto de um contrato já assinado.

### Passos

1. Criar contrato.
2. Ambas as partes assinam.
3. A assinatura aparece como válida.
4. Um atacante/admin malicioso altera `texto_contrato` diretamente na BD.
5. O sistema reconstrói o payload canónico com o novo texto.
6. A verificação da assinatura passa a inválida.

### Resultado

O atacante consegue alterar o conteúdo armazenado, mas não consegue produzir uma assinatura válida sem a chave privada dos assinantes.

Este ataque demonstra a importância das assinaturas digitais para integridade e não repúdio.

---

## Diagramas

O projeto inclui diagramas para documentação/apresentação:

```text
Diagrama_de_App.png
Diagrama_de_BD.png
Diagrama_de_Ataque.png
```


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

Confirma se MariaDB/MySQL está ligado e se o `.env` tem:

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

### `Procedure obrigatória em falta`

A base de dados não tem as stored procedures esperadas. Reexecuta:

```bash
python scripts/init.py
```

---

### `Não foi possível decifrar a chave privada`

A password de login e a password usada para cifrar a chave privada não estão coerentes.

Solução para ambiente demo:

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

## Nota académica

Este projeto é académico/prototípico. Foi desenvolvido para demonstrar conceitos de segurança como autenticação, MFA, criptografia assimétrica, cifra simétrica, HMAC, controlo de acesso, auditoria, stored procedures, triggers e verificação externa.

Numa versão de produção seriam necessários reforços adicionais, incluindo deployment com HTTPS real, gestão segura de segredos, hardening do servidor, monitorização, política de backups e separação de permissões da base de dados.

---

## Licença

Projeto académico. Uso livre para estudo, demonstração e desenvolvimento.

---

## Autor

Desenvolvido no âmbito de Segurança Informática & Cibersegurança.
