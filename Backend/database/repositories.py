"""
Repositorios para acceso a datos
Patrón Repository para separar lógica de negocio de persistencia
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from .connection import get_db


class WorkingKeyRepository:
    """Repositorio para claves de trabajo"""
    
    def create(self, key_id: str, encrypted_data: str, iv: str, 
           tag: str, algorithm: str = "AES-256") -> Dict[str, Any]:
        """Guarda una nueva clave de trabajo encriptada"""
        print(f"🔄 [CREATE] Creando nueva clave: {key_id}")
        
        try:
            with get_db() as conn:
                cursor = conn.execute("""
                    INSERT INTO working_keys (key_id, algorithm, encrypted_data, iv, tag)
                    VALUES (?, ?, ?, ?, ?)
                """, (key_id, algorithm, encrypted_data, iv, tag))
                
                print(f"✅ [CREATE] Clave {key_id} insertada en BD - ID: {cursor.lastrowid}")
                
                # Obtener el registro creado
                result = self.get_by_id(key_id)
                if result:
                    print(f"✅ [CREATE] Clave {key_id} recuperada exitosamente")
                else:
                    print(f"❌ [CREATE] Error recuperando clave {key_id} después de crear")
                
                return result
                
        except Exception as e:
            print(f"❌ [CREATE] ERROR creando clave {key_id}: {str(e)}")
            raise
    
    def get_by_id(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Obtiene una clave por su ID"""
        with get_db() as conn:
            row = conn.execute("""
                SELECT * FROM working_keys WHERE key_id = ? AND is_active = TRUE
            """, (key_id,)).fetchone()
            
            return dict(row) if row else None
    
    def get_all_active(self) -> List[Dict[str, Any]]:
        """Obtiene todas las claves activas"""
        with get_db() as conn:
            rows = conn.execute("""
                SELECT * FROM working_keys 
                WHERE is_active = TRUE 
                ORDER BY created_at DESC
            """).fetchall()
            
            return [dict(row) for row in rows]
    
    def update_usage(self, key_id: str) -> bool:
        """Actualiza el contador de uso y timestamp"""
        with get_db() as conn:
            cursor = conn.execute("""
                UPDATE working_keys 
                SET usage_count = usage_count + 1,
                    last_used_at = CURRENT_TIMESTAMP
                WHERE key_id = ? AND is_active = TRUE
            """, (key_id,))
            
            return cursor.rowcount > 0
    
    def soft_delete(self, key_id: str) -> bool:
        """Marca una clave como inactiva (soft delete)"""
        print(f"🔄 [SOFT_DELETE] Ejecutando para clave: {key_id}")
        
        with get_db() as conn:
            #  VERIFICAR ESTADO ANTES
            row_before = conn.execute("SELECT key_id, is_active FROM working_keys WHERE key_id = ?", (key_id,)).fetchone()
            if row_before:
                print(f"   - ANTES: clave '{row_before['key_id']}' - is_active: {row_before['is_active']}")
            else:
                print(f"   - ANTES: clave '{key_id}' NO EXISTE en BD")
                return False
            
            # Ejecutar soft delete
            cursor = conn.execute("""
                UPDATE working_keys 
                SET is_active = FALSE 
                WHERE key_id = ?
            """, (key_id,))
            
            # ERIFICAR ESTADO DESPUÉS  
            row_after = conn.execute("SELECT key_id, is_active FROM working_keys WHERE key_id = ?", (key_id,)).fetchone()
            if row_after:
                print(f"   - DESPUÉS: clave '{row_after['key_id']}' - is_active: {row_after['is_active']}")
            else:
                print(f"   - DESPUÉS: clave '{key_id}' NO EXISTE en BD")
            
            print(f"   - Filas afectadas: {cursor.rowcount}")
            success = cursor.rowcount > 0
            
            if success:
                print(f"✅ [SOFT_DELETE] Clave {key_id} desactivada exitosamente")
            else:
                print(f"❌ [SOFT_DELETE] Error desactivando clave {key_id}")
                
            return success
    
    def hard_delete(self, key_id: str) -> bool:
        """Elimina permanentemente una clave"""
        print(f"🗑️  [HARD_DELETE] Eliminando físicamente clave: {key_id}")
        
        with get_db() as conn:
            # Verificar si existe antes
            row_before = conn.execute("SELECT 1 FROM working_keys WHERE key_id = ?", (key_id,)).fetchone()
            print(f"   - Clave existe antes: {row_before is not None}")
            
            # Ejecutar eliminación
            cursor = conn.execute("""
                DELETE FROM working_keys WHERE key_id = ?
            """, (key_id,))
            
            # Verificar después
            row_after = conn.execute("SELECT 1 FROM working_keys WHERE key_id = ?", (key_id,)).fetchone()
            print(f"   - Clave existe después: {row_after is not None}")
            print(f"   - Filas eliminadas: {cursor.rowcount}")
            
            success = cursor.rowcount > 0
            
            if success:
                print(f"✅ [HARD_DELETE] Clave {key_id} ELIMINADA FÍSICAMENTE")
            else:
                print(f"❌ [HARD_DELETE] Clave {key_id} NO encontrada para eliminar")
                
            return success
    def exists(self, key_id: str) -> bool:
        """Verifica si una clave existe y está activa"""
        print(f"🔍 [EXISTS] Verificando clave: {key_id}")

        with get_db() as conn:
            row = conn.execute("""
                SELECT key_id, is_active FROM working_keys WHERE key_id = ? AND is_active = TRUE
            """, (key_id,)).fetchone()
            
            exists = row is not None
            print(f"   - EXISTS resultado: {exists}")
            if row:
                print(f"   - Clave encontrada: '{row['key_id']}' - is_active: {row['is_active']}")
            
            return exists
    
    def count_active(self) -> int:
        """Cuenta las claves activas"""
        with get_db() as conn:
            row = conn.execute("""
                SELECT COUNT(*) as count FROM working_keys WHERE is_active = TRUE
            """).fetchone()
            
            return row['count'] if row else 0
    
    def delete_all(self) -> int:
        """Elimina todas las claves (para reset)"""
        with get_db() as conn:
            cursor = conn.execute("DELETE FROM working_keys")
            return cursor.rowcount


class AuditRepository:
    """Repositorio para log de auditoría"""
    
    def log(self, operation: str, details: str, success: bool = True,
            key_id: str = None, data_size: int = None, 
            error_message: str = None, session_id: str = None) -> int:
        """Registra una entrada de auditoría"""
        with get_db() as conn:
            cursor = conn.execute("""
                INSERT INTO audit_log 
                (operation, details, success, key_id, data_size, error_message, session_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (operation, details, success, key_id, data_size, error_message, session_id))
            
            return cursor.lastrowid
    
    def get_recent(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Obtiene las entradas más recientes"""
        with get_db() as conn:
            rows = conn.execute("""
                SELECT * FROM audit_log 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (limit,)).fetchall()
            
            return [dict(row) for row in rows]
    
    def get_by_operation(self, operation: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Obtiene entradas por tipo de operación"""
        with get_db() as conn:
            rows = conn.execute("""
                SELECT * FROM audit_log 
                WHERE operation = ?
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (operation, limit)).fetchall()
            
            return [dict(row) for row in rows]
    
    def get_by_key_id(self, key_id: str) -> List[Dict[str, Any]]:
        """Obtiene historial de una clave específica"""
        with get_db() as conn:
            rows = conn.execute("""
                SELECT * FROM audit_log 
                WHERE key_id = ?
                ORDER BY timestamp DESC
            """, (key_id,)).fetchall()
            
            return [dict(row) for row in rows]
    
    def get_failures(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Obtiene operaciones fallidas"""
        with get_db() as conn:
            rows = conn.execute("""
                SELECT * FROM audit_log 
                WHERE success = FALSE
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (limit,)).fetchall()
            
            return [dict(row) for row in rows]
    
    def get_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas del log"""
        with get_db() as conn:
            row = conn.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as success_count,
                    SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failure_count,
                    MIN(timestamp) as first_entry,
                    MAX(timestamp) as last_entry
                FROM audit_log
            """).fetchone()
            
            return dict(row) if row else {}
    
    def clear(self) -> int:
        """Limpia el log de auditoría"""
        with get_db() as conn:
            cursor = conn.execute("DELETE FROM audit_log")
            return cursor.rowcount
    
    def count(self) -> int:
        """Cuenta total de entradas"""
        with get_db() as conn:
            row = conn.execute("SELECT COUNT(*) as count FROM audit_log").fetchone()
            return row['count'] if row else 0


class ConfigRepository:
    """Repositorio para configuración del HSM"""
    
    def get(self, key: str, default: str = None) -> Optional[str]:
        """Obtiene un valor de configuración"""
        with get_db() as conn:
            row = conn.execute("""
                SELECT value FROM hsm_config WHERE key = ?
            """, (key,)).fetchone()
            
            return row['value'] if row else default
    
    def set(self, key: str, value: str) -> bool:
        """Establece un valor de configuración"""
        with get_db() as conn:
            conn.execute("""
                INSERT INTO hsm_config (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET 
                    value = excluded.value,
                    updated_at = CURRENT_TIMESTAMP
            """, (key, value))
            
            return True
    
    def get_all(self) -> Dict[str, str]:
        """Obtiene toda la configuración"""
        with get_db() as conn:
            rows = conn.execute("SELECT key, value FROM hsm_config").fetchall()
            return {row['key']: row['value'] for row in rows}