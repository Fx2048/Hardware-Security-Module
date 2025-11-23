"""
Gestión del Master Key y componentes de custodios
Implementa división XOR y reconstrucción del master key
"""

from typing import List, Optional
from datetime import datetime
from core.crypto_engine import CryptoEngine


class CustodianComponent:
    """Representa un componente de custodio para el master key"""
    
    def __init__(self, custodian_id: str, key_component: bytes, verification_hash: str):
        self.custodian_id = custodian_id
        self.key_component = key_component
        self.verification_hash = verification_hash
        self.created_at = datetime.now()
    
    def validate_hash(self) -> bool:
        """Valida que el hash de verificación coincida con el componente"""
        computed_hash = CryptoEngine.hash_sha256(self.key_component)
        return computed_hash == self.verification_hash
    
    def to_dict(self) -> dict:
        """Convierte el componente a diccionario para exportación"""
        return {
            'custodian_id': self.custodian_id,
            'key_component': self.key_component.hex(),
            'verification_hash': self.verification_hash,
            'created_at': self.created_at.isoformat()
        }
    
    @staticmethod
    def from_hex(custodian_id: str, component_hex: str, verification_hash: str) -> 'CustodianComponent':
        """Crea un CustodianComponent desde valores hexadecimales"""
        return CustodianComponent(
            custodian_id=custodian_id,
            key_component=bytes.fromhex(component_hex),
            verification_hash=verification_hash
        )


class MasterKeyManager:
    """Gestor del master key y componentes de custodios"""
    
    NUM_CUSTODIANS = 3
    
    def __init__(self):
        self._master_key: Optional[bytes] = None
        self._is_initialized: bool = False
        self._loaded_components: List[CustodianComponent] = []
    
    @property
    def is_loaded(self) -> bool:
        """Verifica si el master key está cargado"""
        return self._is_initialized and self._master_key is not None
    
    def generate_components(self) -> List[CustodianComponent]:
        """
        Genera un master key de 256 bits y lo divide en 3 componentes
        usando esquema XOR (C1 ⊕ C2 ⊕ C3 = MasterKey)
        
        Returns:
            Lista de 3 CustodianComponent
        """
        components = []
        for i in range(self.NUM_CUSTODIANS):
            component_bytes = CryptoEngine.generate_key(32)
            hash_val = CryptoEngine.hash_sha256(component_bytes)
            custodian = CustodianComponent(
                custodian_id=f"CUSTODIAN-{i + 1}",
                key_component=component_bytes,
                verification_hash=hash_val
            )
            components.append(custodian)
        
        # Limpiar estado previo
        self._loaded_components = []
        self._master_key = None
        self._is_initialized = False
        
        return components
    
    def load_component(self, custodian_id: str, component_hex: str, 
                       verification_hash: str) -> bool:
        """
        Carga un componente de custodio después de validar su hash
        
        Returns:
            True si el hash es válido
        """
        try:
            component_bytes = bytes.fromhex(component_hex)
        except ValueError:
            return False
        
        computed_hash = CryptoEngine.hash_sha256(component_bytes)
        if computed_hash != verification_hash:
            return False
        
        # Remover componente anterior del mismo custodio si existe
        self._loaded_components = [
            c for c in self._loaded_components 
            if c.custodian_id != custodian_id
        ]
        
        custodian = CustodianComponent(custodian_id, component_bytes, verification_hash)
        self._loaded_components.append(custodian)
        
        # Si ya tenemos los 3 componentes, reconstruir automáticamente
        if len(self._loaded_components) == self.NUM_CUSTODIANS:
            self._reconstruct_master_key()
        
        return True
    
    def _reconstruct_master_key(self) -> bool:
        """Reconstruye el master key desde los componentes cargados"""
        if len(self._loaded_components) != self.NUM_CUSTODIANS:
            return False
        
        # Validar todos los hashes
        for comp in self._loaded_components:
            if not comp.validate_hash():
                raise ValueError(f"Invalid hash for {comp.custodian_id}")
        
        # Ordenar por custodian_id para consistencia
        sorted_components = sorted(
            self._loaded_components, 
            key=lambda c: c.custodian_id
        )
        
        # Reconstruir: MK = C1 ⊕ C2 ⊕ C3
        result = sorted_components[0].key_component
        for comp in sorted_components[1:]:
            result = CryptoEngine.xor_bytes(result, comp.key_component)
        
        self._master_key = result
        self._is_initialized = True
        return True
    
    def get_master_key(self) -> bytes:
        """Obtiene el master key (solo si está cargado)"""
        if not self.is_loaded:
            raise Exception("Master key not loaded")
        return self._master_key
    
    def get_loaded_count(self) -> int:
        """Retorna cantidad de componentes cargados"""
        return len(self._loaded_components)
    
    def get_loaded_custodians(self) -> List[str]:
        """Retorna lista de IDs de custodios cargados"""
        return [c.custodian_id for c in self._loaded_components]
    
    def clear(self):
        """Limpia el master key y componentes de memoria"""
        if self._master_key:
            self._master_key = bytes(32)  # Sobrescribir
            self._master_key = None
        self._loaded_components = []
        self._is_initialized = False