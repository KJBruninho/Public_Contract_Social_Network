# HTTP/3 com Flask (Guia Completo)

Este projeto suporta HTTP/3 usando Caddy como reverse proxy com QUIC na frente da aplicação Flask.

Arquitetura:

Cliente (browser)
-> Caddy (TLS + HTTP/3)
-> Flask app (HTTP/1.1 em localhost:5000)

Isto é o comportamento esperado: HTTP/3 fica no edge (proxy), e a app Python continua igual por trás.

## 1. Requisitos para qualquer máquina

1. Python 3.8+ e dependências instaladas
2. SQL Server acessível pela aplicação
3. Caddy 2.7+ instalado
4. Portas de rede:
   - 443/TCP
   - 443/UDP (obrigatória para QUIC/HTTP3)
   - 80/TCP (redirect automático HTTP para HTTPS, recomendado)
5. DNS (em produção): domínio apontado para o servidor
6. Firewall do sistema operativo e cloud atualizada para permitir as portas acima

## 2. Configuração da aplicação

Importante: neste projeto, as opções de runtime web são lidas de .flaskenv.

Defina no ficheiro .flaskenv:

TRUST_PROXY=1
SESSION_COOKIE_SECURE=1
PREFERRED_URL_SCHEME=https

Notas:

1. TRUST_PROXY=1 permite que Flask confie no X-Forwarded-Proto/Host do proxy
2. SESSION_COOKIE_SECURE=1 garante cookies apenas em HTTPS
3. PREFERRED_URL_SCHEME=https garante geração de URLs com esquema HTTPS

## 3. Configuração do Caddy

Este repositório já inclui exemplo em [Caddyfile](../Caddyfile).

### Ambiente local

Use localhost no Caddyfile e tls internal.

### Produção

Troque localhost pelo domínio real. Exemplo:

meudominio.com {
encode zstd gzip
reverse_proxy 127.0.0.1:5000
}

Quando usar domínio real, o Caddy emite e renova certificados automaticamente.

## 4. Passos para correr noutra máquina (Windows)

1. Clonar/copiar o projeto
2. Configurar base de dados (ver docs/INSTALACAO.md)
3. Criar e ativar ambiente virtual
4. Instalar dependências Python
5. Configurar .env para SQL Server
6. Configurar .flaskenv com TRUST_PROXY, SESSION_COOKIE_SECURE e PREFERRED_URL_SCHEME
7. Instalar Caddy
8. Ajustar Caddyfile para localhost (local) ou domínio (produção)
9. Arrancar a app Flask em terminal 1:
   python app.py
10. Arrancar Caddy em terminal 2 (na raiz do projeto):
    caddy run --config Caddyfile
11. Aceder por HTTPS:
    https://localhost

## 5. Passos para correr noutra máquina (Linux)

1. Instalar Python, pip, venv, ODBC driver SQL Server, Caddy
2. Clonar projeto
3. Criar venv e instalar requirements
4. Configurar .env e .flaskenv
5. Abrir firewall:
   - sudo ufw allow 80/tcp
   - sudo ufw allow 443/tcp
   - sudo ufw allow 443/udp
6. Arrancar Flask
7. Arrancar Caddy com o Caddyfile

## 6. Instalação rápida do Caddy

### Windows (winget)

winget install --id CaddyServer.Caddy --exact --accept-source-agreements --accept-package-agreements

### Linux (Debian/Ubuntu)

Seguir instalação oficial do Caddy:
https://caddyserver.com/docs/install

## 7. Verificação de HTTP/3

1. Abrir o site em HTTPS
2. Browser DevTools -> Network -> coluna Protocol
3. Esperado: h3

Verificação por log do Caddy:

server running {"protocols":["h1","h2","h3"]}

## 8. Problemas comuns

1. Não abre em HTTPS:
   - confirmar que Caddy está ativo
   - confirmar que a porta 443 está livre

2. Só aparece h1/h2 e não h3:
   - confirmar 443/UDP aberta
   - confirmar que não existe proxy intermédio a bloquear QUIC

3. Erro de certificado local:
   - executar caddy trust
   - no Windows, se necessário, importar o root.crt no store Root do utilizador

4. Login/sessão instável atrás de proxy:
   - confirmar TRUST_PROXY=1
   - confirmar SESSION_COOKIE_SECURE=1

## 9. Operação recomendada em servidor

Para manter sempre ativo após reboot:

1. Flask com serviço (NSSM no Windows ou systemd no Linux)
2. Caddy como serviço do sistema
3. Monitorização de portas 80/443 e saúde da app em 5000

## 10. Limitação importante

Mesmo com HTTP/3 ativo para o cliente, a app Flask continua a correr em HTTP/1.1 atrás do proxy. Isto é normal e recomendado para esta stack.
