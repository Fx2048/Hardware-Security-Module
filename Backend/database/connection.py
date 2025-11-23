"""
Conexión y configuración de base de datos SQLite
"""

import sqlite3
from pathlib import Path
from contextlib import contextmanager
from typing import Generator

# Ruta de la base de datos
DATABASE_PATH = Path(__file__).parent / "hsm_simulator.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def get_connection() -> sqlite3.Connection:
    """Obtiene una conexión a la base de datos"""
    conn = sqlite3.connect(str(DATABASE_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row  # Permite acceso por nombre de columna
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Context manager para conexiones de base de datos"""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_database():
    """Inicializa la base de datos con el schema"""
    with get_db() as conn:
        if SCHEMA_PATH.exists():
            with open(SCHEMA_PATH, 'r', encoding='utf-8') as f:
                conn.executescript(f.read())
        else:
            # Schema inline si no existe el archivo
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS working_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id VARCHAR(50) UNIQUE NOT NULL,
                    algorithm VARCHAR(20) DEFAULT 'AES-256',
                    encrypted_data TEXT NOT NULL,
                    iv TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used_at TIMESTAMP NULL,
                    usage_count INTEGER DEFAULT 0,
                    is_active BOOLEAN DEFAULT TRUE
                );
                
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    operation VARCHAR(50) NOT NULL,
                    details TEXT NOT NULL,
                    success BOOLEAN DEFAULT TRUE,
                    key_id VARCHAR(50) NULL,
                    data_size INTEGER NULL,
                    error_message TEXT NULL,
                    session_id VARCHAR(100) NULL
                );
                
                CREATE TABLE IF NOT EXISTS hsm_config (
                    key VARCHAR(50) PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_working_keys_active ON working_keys(is_active);
            """)
    print(f"✓ Database initialized at {DATABASE_PATH}")


def reset_database():
    """Elimina y recrea la base de datos (solo para desarrollo)"""
    if DATABASE_PATH.exists():
        DATABASE_PATH.unlink()
    init_database()