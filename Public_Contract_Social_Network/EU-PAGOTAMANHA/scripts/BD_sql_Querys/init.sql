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
DROP PROCEDURE IF EXISTS sp_save_signature//
DROP PROCEDURE IF EXISTS sp_mark_sanado//
DROP PROCEDURE IF EXISTS sp_mark_rejeitado//
DROP PROCEDURE IF EXISTS
DROP TRIGGER IF EXISTS trg_contrato_no_self_contract_bi;
DROP TRIGGER IF EXISTS trg_contrato_no_self_contract_bu;
DROP TRIGGER IF EXISTS trg_contrato_reveal_at_check_bi;
DROP TRIGGER IF EXISTS trg_contrato_reveal_at_check_bu;
DROP TRIGGER IF EXISTS trg_assinatura_after_insert;
DROP TRIGGER IF EXISTS trg_assinatura_after_update;
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

CREATE OR REPLACE VIEW v_contratos_com_partes AS
SELECT
    c.*,
    p.nome AS proponente_nome,
    p.email AS proponente_email,
    a.nome AS aceitante_nome,
    a.email AS aceitante_email,
    (
        SELECT COUNT(*)
        FROM assinaturas_contrato s
        WHERE s.id_contrato = c.id
          AND s.assinatura_digital IS NOT NULL
    ) AS assinaturas_count
FROM contratos c
JOIN utilizadores p ON p.id = c.id_proponente
JOIN utilizadores a ON a.id = c.id_aceitante;

CREATE OR REPLACE VIEW v_contratos_publicos AS
SELECT *
FROM v_contratos_com_partes
WHERE visibilidade = 'publico'
  AND estado IN ('assinado', 'sanado');

CREATE OR REPLACE VIEW v_user_security_stats AS
SELECT
    u.id AS id_utilizador,
    COUNT(CASE WHEN l.acao = 'LOGIN_OK' THEN 1 END) AS logins,
    COUNT(CASE WHEN l.sucesso = FALSE THEN 1 END) AS failures,
    COUNT(CASE WHEN l.acao = 'CONTRACT_EXPORTED_OPENSSL_ZIP' THEN 1 END) AS openssl_exports
FROM utilizadores u
LEFT JOIN audit_log l ON l.id_utilizador = u.id
GROUP BY u.id;

CREATE PROCEDURE sp_save_signature(
    IN p_contract_id INT,
    IN p_user_id INT,
    IN p_signature LONGTEXT
)
BEGIN
    UPDATE assinaturas_contrato
    SET assinatura_digital = p_signature,
        data_assinatura = NOW()
    WHERE id_contrato = p_contract_id
      AND id_utilizador = p_user_id
      AND assinatura_digital IS NULL;

    IF ROW_COUNT() = 0 THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Assinatura inexistente, duplicada ou utilizador inválido';
    END IF;
END//

CREATE PROCEDURE sp_mark_sanado(
    IN p_contract_id INT,
    IN p_user_id INT
)
BEGIN
    UPDATE contratos
    SET estado = 'sanado'
    WHERE id = p_contract_id
      AND id_aceitante = p_user_id
      AND estado = 'assinado';

    IF ROW_COUNT() = 0 THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Só o aceitante pode marcar contrato assinado como sanado';
    END IF;
END//

CREATE PROCEDURE sp_mark_rejeitado(
    IN p_contract_id INT,
    IN p_user_id INT
)
BEGIN
    UPDATE contratos
    SET estado = 'rejeitado'
    WHERE id = p_contract_id
      AND estado = 'pendente'
      AND (id_proponente = p_user_id OR id_aceitante = p_user_id);

    IF ROW_COUNT() = 0 THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Só uma parte pode rejeitar contrato pendente';
    END IF;
END//

CREATE PROCEDURE sp_add_audit_log(
    IN p_user_id INT,
    IN p_email VARCHAR(180),
    IN p_action VARCHAR(80),
    IN p_contract_id INT,
    IN p_success BOOLEAN,
    IN p_details TEXT,
    IN p_ip VARCHAR(64),
    IN p_user_agent VARCHAR(255)
)
BEGIN
    INSERT INTO audit_log
    (id_utilizador, email, acao, id_contrato, sucesso, detalhes, ip_address, user_agent)
    VALUES
    (p_user_id, p_email, p_action, p_contract_id, p_success, p_details, p_ip, LEFT(COALESCE(p_user_agent, ''), 255));
END//


CREATE TRIGGER trg_contrato_no_self_contract_bi
BEFORE INSERT ON contratos
FOR EACH ROW
BEGIN
    IF NEW.id_proponente = NEW.id_aceitante THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Proponente e aceitante não podem ser o mesmo utilizador';
    END IF;
END//

CREATE TRIGGER trg_contrato_no_self_contract_bu
BEFORE UPDATE ON contratos
FOR EACH ROW
BEGIN
    IF NEW.id_proponente = NEW.id_aceitante THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Proponente e aceitante não podem ser o mesmo utilizador';
    END IF;
END//

CREATE TRIGGER trg_contrato_reveal_at_check_bi
BEFORE INSERT ON contratos
FOR EACH ROW
BEGIN
    IF NEW.encrypted_text IS NOT NULL AND NEW.reveal_at IS NULL THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Contrato cifrado precisa de reveal_at';
    END IF;
END//

CREATE TRIGGER trg_contrato_reveal_at_check_bu
BEFORE UPDATE ON contratos
FOR EACH ROW
BEGIN
    IF NEW.encrypted_text IS NOT NULL AND NEW.reveal_at IS NULL THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Contrato cifrado precisa de reveal_at';
    END IF;
END//

CREATE TRIGGER trg_assinatura_after_insert
AFTER INSERT ON assinaturas_contrato
FOR EACH ROW
BEGIN
    IF NEW.assinatura_digital IS NOT NULL THEN
        UPDATE contratos
        SET estado = 'assinado'
        WHERE id = NEW.id_contrato
          AND estado = 'pendente'
          AND (
              SELECT COUNT(*)
              FROM assinaturas_contrato
              WHERE id_contrato = NEW.id_contrato
                AND assinatura_digital IS NOT NULL
          ) >= 2;
    END IF;
END//

CREATE TRIGGER trg_assinatura_after_update
AFTER UPDATE ON assinaturas_contrato
FOR EACH ROW
BEGIN
    IF NEW.assinatura_digital IS NOT NULL THEN
        UPDATE contratos
        SET estado = 'assinado'
        WHERE id = NEW.id_contrato
          AND estado = 'pendente'
          AND (
              SELECT COUNT(*)
              FROM assinaturas_contrato
              WHERE id_contrato = NEW.id_contrato
                AND assinatura_digital IS NOT NULL
          ) >= 2;
    END IF;
END//
