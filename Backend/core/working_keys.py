"""
Almacén de claves de trabajo con persistencia en base de datos
"""

from typing import List, Optional
from datetime import datetime
from .crypto_engine import CryptoEngine
from .master_key import MasterKeyManager
from database.repositories import WorkingKeyRepository


class KeyMetadata:
    """Metadatos de una clave de trabajo"""
    
    def __init__(self, key_id: str, algorithm: str = "AES-256",
                 created_at: datetime = None, last_used: datetime = None,
                 usage_count: int = 0):
        self.key_id = key_id
        self.algorithm = algorithm
        self.created_at = created_at or datetime.now()
        self.last_used = last_used
        self.usage_count = usage_count
    
    def to_dict(self) -> dict:
        return {
            'key_id': self.key_id,
            'algorithm': self.algorithm,
            'created_at': self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at,
            'last_used': self.last_used.isoformat() if isinstance(self.last_used, datetime) else self.last_used,
            'usage_count': self.usage_count
        }
    
    @staticmethod
    def from_db_row(row: dict) -> 'KeyMetadata':
        """Crea metadata desde un row de base de datos"""
        return KeyMetadata(
            key_id=row['key_id'],
            algorithm=row['algorithm'],
            created_at=row['created_at'],
            last_used=row.get('last_used_at'),
            usage_count=row.get('usage_count', 0)
        )


class EncryptedWorkingKey:
    """Clave de trabajo encriptada"""
    
    def __init__(self, key_id: str, encrypted_data: bytes, 
                 iv: bytes, tag: bytes, metadata: KeyMetadata):
        self.key_id = key_id
        self.encrypted_data = encrypted_data
        self.iv = iv
        self.tag = tag
        self.metadata = metadata
    
    def to_dict(self) -> dict:
        return {
            'key_id': self.key_id,
            'encrypted_data': self.encrypted_data.hex() if isinstance(self.encrypted_data, bytes) else self.encrypted_data,
            'iv': self.iv.hex() if isinstance(self.iv, bytes) else self.iv,
            'tag': self.tag.hex() if isinstance(self.tag, bytes) else self.tag,
            'metadata': self.metadata.to_dict()
        }
    
    @staticmethod
    def from_db_row(row: dict) -> 'EncryptedWorkingKey':
        """Crea una clave desde un row de base de datos"""
        return EncryptedWorkingKey(
            key_id=row['key_id'],
            encrypted_data=bytes.fromhex(row['encrypted_data']),
            iv=bytes.fromhex(row['iv']),
            tag=bytes.fromhex(row['tag']),
            metadata=KeyMetadata.from_db_row(row)
        )


class WorkingKeyStore:
    """Almacén de claves de trabajo con persistencia"""
    
    def __init__(self, master_key_manager: MasterKeyManager, db_connection=None):
        self._master_key_manager = master_key_manager
        self._repository = WorkingKeyRepository()
        # Cache en memoria de claves desencriptadas (solo durante la sesión)
        self._cache: dict = {}
    
    def generate_key(self, key_id: str) -> EncryptedWorkingKey:
        """Genera una nueva clave de trabajo y la persiste"""
        if not self._master_key_manager.is_loaded:
            raise Exception("Master key must be loaded first")
        print(f"🔍 [GENERATE_KEY] Verificando clave: {key_id}")
        print(f"   - Repository.exists(): {self._repository.exists(key_id)}")

        if self._repository.exists(key_id):
            print(f"❌ [GENERATE_KEY] Clave {key_id} YA EXISTE (activa)")
            raise ValueError(f"Key '{key_id}' already exists")
        else:
            print(f"✅ [GENERATE_KEY] Clave {key_id} NO EXISTE (activa) - procediendo...")
        # Generar clave de trabajo
        working_key = CryptoEngine.generate_key(32)
        
        # Encriptar con master key
        master_key = self._master_key_manager.get_master_key()
        ciphertext, iv, tag = CryptoEngine.encrypt_aes_gcm(working_key, master_key)
        
        # Persistir en base de datos
        self._repository.create(
            key_id=key_id,
            encrypted_data=ciphertext.hex(),
            iv=iv.hex(),
            tag=tag.hex(),
            algorithm="AES-256"
        )
        
        # Obtener registro completo con timestamps
        row = self._repository.get_by_id(key_id)
        return EncryptedWorkingKey.from_db_row(row)
    
    def get_decrypted_key(self, key_id: str) -> bytes:
        """Obtiene una clave de trabajo desencriptada"""
        if not self._master_key_manager.is_loaded:
            raise Exception("Master key must be loaded first")
        
        row = self._repository.get_by_id(key_id)
        if not row:
            raise ValueError(f"Key '{key_id}' not found")
        
        encrypted_key = EncryptedWorkingKey.from_db_row(row)
        master_key = self._master_key_manager.get_master_key()
        
        working_key = CryptoEngine.decrypt_aes_gcm(
            encrypted_key.encrypted_data,
            master_key,
            encrypted_key.iv,
            encrypted_key.tag
        )
        
        # Actualizar estadísticas de uso
        self._repository.update_usage(key_id)
        
        return working_key
    
    def delete_key(self, key_id: str) -> bool:
        """Elimina una clave de trabajo (soft delete)"""
        print(f"Eliminando clave: {key_id}")
        print(f"    -Cache antes: {list(self._cache.keys())} ")


        success = self._repository.hard_delete(key_id)

        if success:
            # LIMPIAR LA CLAVE DE LA CACHE
            self._cache.pop(key_id, None)
            print(f" Clave {key_id} eliminada - Cache limpiada")
            print(f"Cache despues: {self._cache.keys()}")
        else:
            print(f"Error eliminando la clave{key_id}")
        
        return success
    
    def list_keys(self) -> List[dict]:
        """Lista todas las claves activas"""
        # FORZAR recarga desde BD, no usar cache
        print(f"Listando claves de la BD ...")
        rows = self._repository.get_all_active()
        keys = [EncryptedWorkingKey.from_db_row(row).to_dict() for row in rows]
        print(f"{len(keys)} claves encontradas en BD")
        
        # ACTUALIZAR cache con los datos frescos
        for key in keys:
            self._cache[key['key_id']] = key
            
        return keys
    
    def get_key_info(self, key_id: str) -> Optional[dict]:
        """Obtiene información de una clave específica"""
        row = self._repository.get_by_id(key_id)
        if row:
            return EncryptedWorkingKey.from_db_row(row).to_dict()
        return None
    
    def key_exists(self, key_id: str) -> bool:
        return self._repository.exists(key_id)
    
    @property
    def count(self) -> int:
        return self._repository.count_active()
    
    def clear_all(self):
        """Limpia solo el cache de memoria"""
        self._cache.clear()