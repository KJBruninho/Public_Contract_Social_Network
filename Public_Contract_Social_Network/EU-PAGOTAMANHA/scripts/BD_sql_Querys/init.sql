-- EU-PAGOTAMANHÃ - MySQL 8 schema
-- Cria a base de dados e todas as tabelas necessárias para a app Flask.

CREATE DATABASE IF NOT EXISTS EUPagoAmanhaDB
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE EUPagoAmanhaDB;

SET FOREIGN_KEY_CHECKS = 0;
DROP VIEW IF EXISTS v_ContratosPublicos;
DROP VIEW IF EXISTS v_PerfisPublicos;
DROP TABLE IF EXISTS auditoria_contratos;
DROP TABLE IF EXISTS assinaturas_contrato;
DROP TABLE IF EXISTS chaves_utilizador;
DROP TABLE IF EXISTS password_history;
DROP TABLE IF EXISTS contratos;
DROP TABLE IF EXISTS utilizadores;
SET FOREIGN_KEY_CHECKS = 1;

-- UTILIZADORES
CREATE TABLE utilizadores (
    id_utilizador INT NOT NULL AUTO_INCREMENT,
    nome VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(512) NOT NULL,
    hmac_type VARCHAR(20) NOT NULL DEFAULT 'HMAC-SHA256',
    mfa_enabled TINYINT(1) NOT NULL DEFAULT 0,
    mfa_secret VARCHAR(64) NULL,
    password_changed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    active_session_id VARCHAR(128) NULL,
    active_session_ip VARCHAR(64) NULL,
    active_session_updated_at DATETIME NULL,
    data_criacao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id_utilizador),
    UNIQUE KEY UQ_utilizadores_email (email),
    CONSTRAINT CHK_utilizadores_hmac_type
        CHECK (hmac_type IN ('HMAC-SHA256', 'HMAC-SHA512'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- PASSWORD HISTORY
CREATE TABLE password_history (
    id_history INT NOT NULL AUTO_INCREMENT,
    id_utilizador INT NOT NULL,
    password_hash VARCHAR(512) NOT NULL,
    changed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id_history),
    KEY IX_password_history_user_changed (id_utilizador, changed_at DESC, id_history DESC),
    CONSTRAINT FK_password_history_utilizador
        FOREIGN KEY (id_utilizador)
        REFERENCES utilizadores(id_utilizador)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- CHAVES UTILIZADOR (1:1)
CREATE TABLE chaves_utilizador (
    id_chave INT NOT NULL AUTO_INCREMENT,
    id_utilizador INT NOT NULL,
    chave_publica LONGTEXT NOT NULL,
    chave_privada_cifrada LONGTEXT NOT NULL,
    iv_chave VARCHAR(64) NOT NULL,
    data_criacao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id_chave),
    UNIQUE KEY UQ_chaves_id_utilizador (id_utilizador),
    KEY IX_Chaves_Utilizador (id_utilizador),
    CONSTRAINT FK_Chaves_Utilizador
        FOREIGN KEY (id_utilizador)
        REFERENCES utilizadores(id_utilizador)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- CONTRATOS
CREATE TABLE contratos (
    id_contrato INT NOT NULL AUTO_INCREMENT,
    texto_contrato LONGTEXT NOT NULL,
    data_criacao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    data_desbloqueio DATETIME NULL,
    algoritmo_cifra VARCHAR(50) NOT NULL DEFAULT 'AES-256-CBC',
    estado VARCHAR(20) NOT NULL DEFAULT 'ativo',

    PRIMARY KEY (id_contrato),
    CONSTRAINT CHK_Algoritmo
        CHECK (algoritmo_cifra IN ('AES-256-CBC', 'AES-256-CTR')),
    CONSTRAINT CHK_Estado
        CHECK (estado IN ('ativo', 'concluido'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ASSINATURAS
CREATE TABLE assinaturas_contrato (
    id_assinatura INT NOT NULL AUTO_INCREMENT,
    id_contrato INT NOT NULL,
    id_utilizador INT NOT NULL,
    assinatura_digital LONGTEXT NULL,
    tipo_assinante VARCHAR(20) NOT NULL,
    data_assinatura DATETIME DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id_assinatura),
    UNIQUE KEY UQ_Assinatura_Unica (id_contrato, id_utilizador),
    KEY IX_Assinaturas_Contrato (id_contrato),
    KEY IX_Assinaturas_Utilizador (id_utilizador),
    CONSTRAINT CHK_Tipo_Assinante
        CHECK (tipo_assinante IN ('proponente', 'aceitante')),
    CONSTRAINT FK_Assinatura_Contrato
        FOREIGN KEY (id_contrato)
        REFERENCES contratos(id_contrato)
        ON DELETE CASCADE,
    CONSTRAINT FK_Assinatura_Utilizador
        FOREIGN KEY (id_utilizador)
        REFERENCES utilizadores(id_utilizador)
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- AUDITORIA
CREATE TABLE auditoria_contratos (
    id_log INT NOT NULL AUTO_INCREMENT,
    id_contrato INT NOT NULL,
    evento VARCHAR(100) NOT NULL,
    data_evento DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    detalhes LONGTEXT NULL,

    PRIMARY KEY (id_log),
    KEY IX_Auditoria_Contrato (id_contrato),
    CONSTRAINT FK_Auditoria_Contrato
        FOREIGN KEY (id_contrato)
        REFERENCES contratos(id_contrato)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- VIEWS
CREATE VIEW v_PerfisPublicos AS
SELECT
    u.id_utilizador,
    u.nome,
    u.email,
    u.data_criacao,
    cu.chave_publica
FROM utilizadores u
LEFT JOIN chaves_utilizador cu
    ON u.id_utilizador = cu.id_utilizador;

CREATE VIEW v_ContratosPublicos AS
SELECT
    c.id_contrato,
    c.texto_contrato,
    c.data_criacao,
    c.data_desbloqueio,
    c.algoritmo_cifra,
    c.estado,
    up.nome AS proponente_nome,
    ua.nome AS aceitante_nome,
    ap.id_utilizador AS proponente_id,
    aa.id_utilizador AS aceitante_id,
    ap.assinatura_digital AS proponente_assinatura,
    aa.assinatura_digital AS aceitante_assinatura
FROM contratos c
JOIN assinaturas_contrato ap
    ON c.id_contrato = ap.id_contrato
   AND ap.tipo_assinante = 'proponente'
JOIN assinaturas_contrato aa
    ON c.id_contrato = aa.id_contrato
   AND aa.tipo_assinante = 'aceitante'
JOIN utilizadores up
    ON ap.id_utilizador = up.id_utilizador
JOIN utilizadores ua
    ON aa.id_utilizador = ua.id_utilizador;

