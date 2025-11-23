"""
Orquestador principal del HSM - Integra todos los componentes
"""

from typing import List, Tuple
from dataclasses import dataclass
from .crypto_engine import CryptoEngine
from .master_key import MasterKeyManager, CustodianComponent
from .working_keys import WorkingKeyStore
import time

@dataclass
class EncryptedData:
    """Datos encriptados con metadata"""
    ciphertext: bytes
    iv: bytes
    tag: bytes
    key_id: str
    algorithm: str = "AES-256-GCM"
    
    def to_dict(self) -> dict:
        return {
            'ciphertext': self.ciphertext.hex(),
            'iv': self.iv.hex(),
            'tag': self.tag.hex(),
            'key_id': self.key_id,
            'algorithm': self.algorithm
        }
    
    @staticmethod
    def from_dict(data: dict) -> 'EncryptedData':
        return EncryptedData(
            ciphertext=bytes.fromhex(data['ciphertext']),
            iv=bytes.fromhex(data['iv']),
            tag=bytes.fromhex(data['tag']),
            key_id=data['key_id'],
            algorithm=data.get('algorithm', 'AES-256-GCM')
        )


class HSMSimulator:
    """Simulador principal del Hardware Security Module"""
    
    def __init__(self):
        self.master_key_manager = MasterKeyManager()
        self.key_store = WorkingKeyStore(self.master_key_manager)
        self.last_activity=None
        self.session_timeout=2*60
    
    def _check_activity(self):
        """Verifica y actualiza actividad - LLAMAR EN CADA MÉTODO"""
        current_time = time.time()
        
        # Si hay inactividad prolongada, resetear
        if (self.last_activity and 
            (current_time - self.last_activity) > self.session_timeout and
            self.master_key_manager.is_loaded):
            self.reset()
            raise Exception("HSM session expired due to inactivity")
        
        self.last_activity = current_time
    # Base
    
    def generate_master_key(self) -> List[dict]:
        """Genera master key y retorna componentes de custodios"""
        components = self.master_key_manager.generate_components()
        return [c.to_dict() for c in components]
    
    def load_custodian(self, custodian_id: str, component_hex: str, 
                       verification_hash: str) -> Tuple[bool, str]:
        """
        Carga un componente de custodio
        
        Returns:
            Tuple[success, message]
        """
        self._check_activity() 

        success = self.master_key_manager.load_component(
            custodian_id, component_hex, verification_hash
        )
        
        if not success:
            return False, "Hash verification failed"
        
        loaded = self.master_key_manager.get_loaded_count()
        
        if self.master_key_manager.is_loaded:
            return True, "Master key reconstructed successfully"
        
        return True, f"Component loaded ({loaded}/3)"
    
    # ==================== KEYS ====================
    
    def generate_working_key(self, key_id: str) -> dict:
        """Genera una nueva clave de trabajo"""
        self._check_activity()
        encrypted_key = self.key_store.generate_key(key_id)
        return encrypted_key.to_dict()
    
    def list_working_keys(self) -> List[dict]:
        """Lista todas las claves de trabajo"""
        return self.key_store.list_keys()
    
    def delete_working_key(self, key_id: str) -> bool:
        """Elimina una clave de trabajo"""
        return self.key_store.delete_key(key_id)
    
    # ==================== CRYPTO ====================
    
    def encrypt(self, plaintext: bytes, key_id: str) -> EncryptedData:
        """Encripta datos con una clave de trabajo"""
        self._check_activity()
        if not self.key_store.key_exists(key_id):
            raise ValueError(f"Key '{key_id}' not found")
        
        working_key = self.key_store.get_decrypted_key(key_id)
        ciphertext, iv, tag = CryptoEngine.encrypt_aes_gcm(plaintext, working_key)
        
        return EncryptedData(
            ciphertext=ciphertext,
            iv=iv,
            tag=tag,
            key_id=key_id
        )
    
    def decrypt(self, encrypted_data: EncryptedData) -> bytes:
        """Desencripta datos"""
        self._check_activity()
        if not self.key_store.key_exists(encrypted_data.key_id):
            raise ValueError(f"Key '{encrypted_data.key_id}' not found")
        
        working_key = self.key_store.get_decrypted_key(encrypted_data.key_id)
        
        return CryptoEngine.decrypt_aes_gcm(
            encrypted_data.ciphertext,
            working_key,
            encrypted_data.iv,
            encrypted_data.tag
        )
    
    # ==================== STATUS ====================
    
    def get_status(self) -> dict:
        """Obtiene el estado actual del HSM"""
        return {
            'master_key_loaded': self.master_key_manager.is_loaded,
            'loaded_custodians': self.master_key_manager.get_loaded_custodians(),
            'custodians_loaded': self.master_key_manager.get_loaded_count(),
            'custodians_required': 3,
            'working_keys_count': self.key_store.count,
            'status': 'operational' if self.master_key_manager.is_loaded else 'standby'
        }
    
    def reset(self):
        """Reinicia el HSM completamente"""
        self.master_key_manager.clear()
        self.key_store.clear_all()