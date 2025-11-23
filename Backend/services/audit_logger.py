"""
Sistema de auditoría con persistencia en base de datos
"""

from typing import List, Dict, Any
from database.repositories import AuditRepository


class AuditLogger:
    """Sistema de auditoría persistente"""
    
    def __init__(self, session_id: str = None):
        self._repository = AuditRepository()
        self._session_id = session_id
    
    def log(self, operation: str, details: str, success: bool = True,
            key_id: str = None, data_size: int = None, error_message: str = None):
        """Registra una operación en el log de auditoría"""
        self._repository.log(
            operation=operation,
            details=details,
            success=success,
            key_id=key_id,
            data_size=data_size,
            error_message=error_message,
            session_id=self._session_id
        )
    
    # Métodos de conveniencia para operaciones comunes
    def log_master_key_generated(self):
        self.log("MASTER_KEY_GENERATION", "Master key generated and split into 3 components")
    
    def log_custodian_load(self, custodian_id: str, success: bool = True):
        status = "loaded successfully" if success else "verification failed"
        self.log(
            "CUSTODIAN_LOAD", 
            f"Custodian '{custodian_id}' {status}", 
            success=success,
            error_message=None if success else "Hash verification failed"
        )
    
    def log_master_key_reconstructed(self):
        self.log("MASTER_KEY_RECONSTRUCTED", "Master key reconstructed from custodian components")
    
    def log_key_generation(self, key_id: str):
        self.log("KEY_GENERATION", f"Working key '{key_id}' generated", key_id=key_id)
    
    def log_key_deletion(self, key_id: str):
        self.log("KEY_DELETION", f"Working key '{key_id}' deleted", key_id=key_id)
    
    def log_encryption(self, key_id: str, data_size: int):
        self.log(
            "ENCRYPTION", 
            f"Data encrypted with key '{key_id}' ({data_size} bytes)",
            key_id=key_id,
            data_size=data_size
        )
    
    def log_decryption(self, key_id: str, success: bool = True, data_size: int = None):
        status = "successful" if success else "failed"
        self.log(
            "DECRYPTION", 
            f"Decryption with key '{key_id}' {status}",
            success=success,
            key_id=key_id,
            data_size=data_size,
            error_message=None if success else "Decryption failed"
        )
    
    def log_hsm_reset(self):
        self.log("HSM_RESET", "HSM state cleared")
    
    def log_error(self, operation: str, error_message: str, key_id: str = None):
        self.log(
            operation,
            f"Error: {error_message}",
            success=False,
            key_id=key_id,
            error_message=error_message
        )
    
    # Métodos de consulta
    def get_entries(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Obtiene las últimas N entradas"""
        return self._repository.get_recent(limit)
    
    def get_all(self) -> List[Dict[str, Any]]:
        """Obtiene todas las entradas"""
        return self._repository.get_recent(10000)
    
    def get_by_key(self, key_id: str) -> List[Dict[str, Any]]:
        """Obtiene historial de una clave específica"""
        return self._repository.get_by_key_id(key_id)
    
    def get_failures(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Obtiene operaciones fallidas"""
        return self._repository.get_failures(limit)
    
    def get_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas del log"""
        return self._repository.get_stats()
    
    @property
    def count(self) -> int:
        return self._repository.count()
    
    def clear(self):
        """Limpia el log de auditoría"""
        self._repository.clear()


# Singleton global para el logger
audit_logger = AuditLogger()