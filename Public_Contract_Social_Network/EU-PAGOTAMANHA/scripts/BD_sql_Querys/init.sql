CREATE DATABASE IF NOT EXISTS EUPagoAmanhaDB
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE EUPagoAmanhaDB;

SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS password_history;
DROP TABLE IF EXISTS assinaturas_contrato;
DROP TABLE IF EXISTS contratos;
DROP TABLE IF EXISTS chaves_utilizador;
DROP TABLE IF EXISTS utilizadores;
SET FOREIGN_KEY_CHECKS = 1;

CREATE TABLE utilizadores (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nome VARCHAR(120) NOT NULL,
    email VARCHAR(180) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    data_registo DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret VARCHAR(255) NULL,
    password_changed_at DATETIME NULL,
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    INDEX idx_utilizadores_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE chaves_utilizador (
    id INT AUTO_INCREMENT PRIMARY KEY,
    id_utilizador INT NOT NULL UNIQUE,
    public_key LONGTEXT NOT NULL,
    encrypted_private_key LONGTEXT NOT NULL,
    private_key_salt VARCHAR(255) NOT NULL,
    private_key_iv VARCHAR(255) NOT NULL,
    private_key_algorithm VARCHAR(50) NOT NULL DEFAULT 'AES-256-CBC',
    data_criacao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_chaves_user FOREIGN KEY (id_utilizador)
        REFERENCES utilizadores(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE contratos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    titulo VARCHAR(180) NOT NULL,
    texto_contrato LONGTEXT NOT NULL,
    id_proponente INT NOT NULL,
    id_aceitante INT NOT NULL,
    estado ENUM('pendente','assinado','sanado','rejeitado') NOT NULL DEFAULT 'pendente',
    visibilidade ENUM('publico','privado') NOT NULL DEFAULT 'publico',
    data_criacao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    data_atualizacao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    encrypted_text LONGTEXT NULL,
    encryption_iv VARCHAR(255) NULL,
    encryption_salt VARCHAR(255) NULL,
    encryption_algorithm VARCHAR(50) NULL,
    hmac_algorithm VARCHAR(50) NULL,
    hmac_value LONGTEXT NULL,
    reveal_at DATETIME NULL,
    CONSTRAINT fk_contratos_prop FOREIGN KEY (id_proponente)
        REFERENCES utilizadores(id) ON DELETE CASCADE,
    CONSTRAINT fk_contratos_aceit FOREIGN KEY (id_aceitante)
        REFERENCES utilizadores(id) ON DELETE CASCADE,
    INDEX idx_contratos_estado (estado),
    INDEX idx_contratos_prop (id_proponente),
    INDEX idx_contratos_aceit (id_aceitante),
    INDEX idx_contratos_publicos (visibilidade, estado)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE assinaturas_contrato (
    id INT AUTO_INCREMENT PRIMARY KEY,
    id_contrato INT NOT NULL,
    id_utilizador INT NOT NULL,
    tipo_assinante ENUM('proponente','aceitante') NOT NULL,
    assinatura_digital LONGTEXT NULL,
    data_assinatura DATETIME NULL,
    CONSTRAINT fk_assinaturas_contrato FOREIGN KEY (id_contrato)
        REFERENCES contratos(id) ON DELETE CASCADE,
    CONSTRAINT fk_assinaturas_user FOREIGN KEY (id_utilizador)
        REFERENCES utilizadores(id) ON DELETE CASCADE,
    UNIQUE KEY uq_assinatura_parte (id_contrato, id_utilizador, tipo_assinante)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE password_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    id_utilizador INT NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    data_criacao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_password_history_user FOREIGN KEY (id_utilizador)
        REFERENCES utilizadores(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
