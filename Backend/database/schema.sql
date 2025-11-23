-- HSM Simulator Database Schema
-- Base de datos: SQLite

-- ============================================
-- TABLA: working_keys
-- Almacena claves de trabajo encriptadas
-- NOTA: La clave está encriptada con el master key,
--       por lo que sin el master key son inútiles
-- ============================================
CREATE TABLE IF NOT EXISTS working_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id VARCHAR(50) UNIQUE NOT NULL,
    algorithm VARCHAR(20) DEFAULT 'AES-256',
    
    -- Clave encriptada con master key (hex)
    encrypted_data TEXT NOT NULL,
    iv TEXT NOT NULL,
    tag TEXT NOT NULL,
    
    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP NULL,
    usage_count INTEGER DEFAULT 0,
    
    -- Estado
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Índices para búsqueda rápida
    CONSTRAINT uk_key_id UNIQUE (key_id)
);

CREATE INDEX IF NOT EXISTS idx_working_keys_active ON working_keys(is_active);
CREATE INDEX IF NOT EXISTS idx_working_keys_created ON working_keys(created_at);

-- ============================================
-- TABLA: audit_log
-- Registro inmutable de todas las operaciones
-- Crítico para compliance y seguridad
-- ============================================
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Operación realizada
    operation VARCHAR(50) NOT NULL,
    details TEXT NOT NULL,
    success BOOLEAN DEFAULT TRUE,
    
    -- Contexto adicional (opcional)
    key_id VARCHAR(50) NULL,
    data_size INTEGER NULL,
    error_message TEXT NULL,
    
    -- Para trazabilidad (en producción sería user_id)
    session_id VARCHAR(100) NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_operation ON audit_log(operation);
CREATE INDEX IF NOT EXISTS idx_audit_key_id ON audit_log(key_id);

-- ============================================
-- TABLA: hsm_config
-- Configuración persistente del HSM
-- ============================================
CREATE TABLE IF NOT EXISTS hsm_config (
    key VARCHAR(50) PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Configuración inicial
INSERT OR IGNORE INTO hsm_config (key, value) VALUES 
    ('hsm_version', '1.0.0'),
    ('default_algorithm', 'AES-256-GCM'),
    ('max_keys', '100'),
    ('audit_retention_days', '90');

-- ============================================
-- VISTA: audit_summary
-- Resumen de actividad para dashboards
-- ============================================
CREATE VIEW IF NOT EXISTS audit_summary AS
SELECT 
    DATE(timestamp) as date,
    operation,
    COUNT(*) as count,
    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as success_count,
    SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failure_count
FROM audit_log
GROUP BY DATE(timestamp), operation
ORDER BY date DESC, operation;

-- ============================================
-- VISTA: active_keys_summary
-- Resumen de claves activas
-- ============================================
CREATE VIEW IF NOT EXISTS active_keys_summary AS
SELECT 
    COUNT(*) as total_keys,
    SUM(usage_count) as total_operations,
    MAX(last_used_at) as last_activity
FROM working_keys
WHERE is_active = TRUE;