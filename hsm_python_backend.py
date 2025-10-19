"""
HSM Simulator - Hardware Security Module
Implementación Backend en Python

Módulos principales:
- CryptoEngine: Motor criptográfico (AES-256-GCM, SHA-256)
- MasterKeyManager: Gestión de master key y custodios
- WorkingKeyStore: Almacén de claves de trabajo
- HSMSimulator: Orquestador principal
- AuditLogger: Sistema de auditoría
"""

import os
import json
import hashlib
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets


class CustodianComponent:
    """Representa un componente de custodio para el master key"""
    
    def __init__(self, custodian_id: str, key_component: bytes, verification_hash: str):
        self.custodian_id = custodian_id
        self.key_component = key_component
        self.verification_hash = verification_hash
        self.created_at = datetime.now()
    
    def validate_hash(self) -> bool:
        """Valida que el hash de verificación coincida con el componente"""
        computed_hash = hashlib.sha256(self.key_component).hexdigest()
        return computed_hash == self.verification_hash
    
    def to_dict(self) -> Dict:
        """Convierte el componente a diccionario para exportación"""
        return {
            'custodian_id': self.custodian_id,
            'key_component': self.key_component.hex(),
            'verification_hash': self.verification_hash,
            'created_at': self.created_at.isoformat()
        }
    
    @staticmethod
    def from_dict(data: Dict) -> 'CustodianComponent':
        """Crea un CustodianComponent desde un diccionario"""
        component = CustodianComponent(
            custodian_id=data['custodian_id'],
            key_component=bytes.fromhex(data['key_component']),
            verification_hash=data['verification_hash']
        )
        component.created_at = datetime.fromisoformat(data['created_at'])
        return component


class KeyMetadata:
    """Metadatos de una clave de trabajo"""
    
    def __init__(self, key_id: str, algorithm: str, key_length: int, purpose: str = "general"):
        self.key_id = key_id
        self.algorithm = algorithm
        self.key_length = key_length
        self.created_at = datetime.now()
        self.last_used = None
        self.purpose = purpose
        self.usage_count = 0
    
    def update_usage(self):
        """Actualiza el timestamp de último uso"""
        self.last_used = datetime.now()
        self.usage_count += 1
    
    def to_dict(self) -> Dict:
        return {
            'key_id': self.key_id,
            'algorithm': self.algorithm,
            'key_length': self.key_length,
            'created_at': self.created_at.isoformat(),
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'purpose': self.purpose,
            'usage_count': self.usage_count
        }


class EncryptedKey:
    """Representa una clave de trabajo encriptada con el master key"""
    
    def __init__(self, key_id: str, algorithm: str, encrypted_data: bytes, 
                 iv: bytes, tag: bytes, metadata: KeyMetadata):
        self.key_id = key_id
        self.algorithm = algorithm
        self.encrypted_data = encrypted_data
        self.iv = iv
        self.tag = tag
        self.metadata = metadata
        self.created_at = datetime.now()
    
    def to_dict(self) -> Dict:
        return {
            'key_id': self.key_id,
            'algorithm': self.algorithm,
            'encrypted_data': self.encrypted_data.hex(),
            'iv': self.iv.hex(),
            'tag': self.tag.hex(),
            'metadata': self.metadata.to_dict(),
            'created_at': self.created_at.isoformat()
        }


class EncryptedData:
    """Representa datos encriptados"""
    
    def __init__(self, ciphertext: bytes, iv: bytes, tag: bytes, 
                 algorithm: str, mode: str, key_id: str):
        self.ciphertext = ciphertext
        self.iv = iv
        self.tag = tag
        self.algorithm = algorithm
        self.mode = mode
        self.key_id = key_id
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict:
        return {
            'ciphertext': self.ciphertext.hex(),
            'iv': self.iv.hex(),
            'tag': self.tag.hex(),
            'algorithm': self.algorithm,
            'mode': self.mode,
            'key_id': self.key_id,
            'timestamp': self.timestamp.isoformat()
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
    
    @staticmethod
    def from_dict(data: Dict) -> 'EncryptedData':
        return EncryptedData(
            ciphertext=bytes.fromhex(data['ciphertext']),
            iv=bytes.fromhex(data['iv']),
            tag=bytes.fromhex(data['tag']),
            algorithm=data['algorithm'],
            mode=data['mode'],
            key_id=data['key_id']
        )


class CryptoEngine:
    """Motor criptográfico para operaciones de encriptación/desencriptación"""
    
    @staticmethod
    def generate_key(key_size: int = 32) -> bytes:
        """Genera una clave criptográfica segura usando CSPRNG"""
        return secrets.token_bytes(key_size)
    
    @staticmethod
    def generate_iv(iv_size: int = 12) -> bytes:
        """Genera un IV (Initialization Vector) seguro"""
        return secrets.token_bytes(iv_size)
    
    @staticmethod
    def hash_sha256(data: bytes) -> str:
        """Calcula el hash SHA-256 de los datos"""
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def encrypt_aes_gcm(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encripta datos usando AES-256-GCM
        
        Returns:
            Tuple[ciphertext, iv, tag]
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for AES-256")
        
        iv = CryptoEngine.generate_iv(12)
        aesgcm = AESGCM(key)
        
        # AES-GCM devuelve ciphertext con tag incluido al final
        ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)
        
        # Separar ciphertext y tag (últimos 16 bytes son el tag)
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]
        
        return ciphertext, iv, tag
    
    @staticmethod
    def decrypt_aes_gcm(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
        """
        Desencripta datos usando AES-256-GCM
        
        Raises:
            Exception: Si la autenticación falla (datos modificados)
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for AES-256")
        
        aesgcm = AESGCM(key)
        
        # Recombinar ciphertext y tag
        ciphertext_with_tag = ciphertext + tag
        
        try:
            plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, None)
            return plaintext
        except Exception as e:
            raise Exception(f"Decryption failed - data may be corrupted or tampered: {str(e)}")
    
    @staticmethod
    def xor_bytes(a: bytes, b: bytes) -> bytes:
        """XOR entre dos arrays de bytes"""
        if len(a) != len(b):
            raise ValueError("Byte arrays must be same length for XOR")
        return bytes(x ^ y for x, y in zip(a, b))


class AuditEntry:
    """Entrada de registro de auditoría"""
    
    def __init__(self, operation: str, details: str, success: bool = True, user_id: str = "system"):
        self.timestamp = datetime.now()
        self.operation = operation
        self.details = details
        self.success = success
        self.user_id = user_id
    
    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp.isoformat(),
            'operation': self.operation,
            'details': self.details,
            'success': self.success,
            'user_id': self.user_id
        }


class AuditLogger:
    """Sistema de auditoría para el HSM"""
    
    def __init__(self, log_file: str = "hsm_audit.log"):
        self.log_file = log_file
        self.entries: List[AuditEntry] = []
    
    def log_operation(self, operation: str, details: str, success: bool = True, user_id: str = "system"):
        """Registra una operación en el log de auditoría"""
        entry = AuditEntry(operation, details, success, user_id)
        self.entries.append(entry)
        
        # Escribir a archivo
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry.to_dict()) + '\n')
    
    def log_key_generation(self, key_id: str):
        self.log_operation("KEY_GENERATION", f"Working key '{key_id}' generated")
    
    def log_encryption(self, key_id: str, data_size: int):
        self.log_operation("DATA_ENCRYPTION", f"Data encrypted with key '{key_id}' (size: {data_size} bytes)")
    
    def log_decryption(self, key_id: str, data_size: int, success: bool = True):
        self.log_operation("DATA_DECRYPTION", f"Data decrypted with key '{key_id}' (size: {data_size} bytes)", success)
    
    def log_custodian_load(self, custodian_id: str, success: bool = True):
        status = "loaded successfully" if success else "failed verification"
        self.log_operation("CUSTODIAN_LOAD", f"Custodian '{custodian_id}' {status}", success)
    
    def get_audit_trail(self) -> List[Dict]:
        """Obtiene el trail de auditoría completo"""
        return [entry.to_dict() for entry in self.entries]
    
    def export_log(self, format: str = "json") -> str:
        """Exporta el log en el formato especificado"""
        if format == "json":
            return json.dumps(self.get_audit_trail(), indent=2)
        else:
            raise ValueError(f"Format '{format}' not supported")


class MasterKeyManager:
    """Gestor del master key y componentes de custodios"""
    
    def __init__(self):
        self.master_key: Optional[bytes] = None
        self.is_initialized: bool = False
        self.components: List[CustodianComponent] = []
    
    def generate_master_key(self) -> List[CustodianComponent]:
        """
        Genera un master key de 256 bits y lo divide en 3 componentes
        usando un esquema XOR (C1 ⊕ C2 ⊕ C3 = MasterKey)
        
        Returns:
            Lista de 3 CustodianComponent
        """
        # Generar 3 componentes aleatorios
        c1 = CryptoEngine.generate_key(32)
        c2 = CryptoEngine.generate_key(32)
        c3 = CryptoEngine.generate_key(32)
        
        # El master key es el XOR de los 3 componentes
        # MK = C1 ⊕ C2 ⊕ C3
        master_key = CryptoEngine.xor_bytes(CryptoEngine.xor_bytes(c1, c2), c3)
        
        # Crear componentes con hashes de verificación
        components = []
        for i, component in enumerate([c1, c2, c3], 1):
            hash_val = CryptoEngine.hash_sha256(component)
            custodian = CustodianComponent(
                custodian_id=f"CUSTODIAN-{i}",
                key_component=component,
                verification_hash=hash_val
            )
            components.append(custodian)
        
        self.components = components
        
        # Por seguridad, no almacenamos el master key generado
        # Los custodios deben cargarlo manualmente
        
        return components
    
    def load_custodian_component(self, custodian_id: str, component: bytes, 
                                  verification_hash: str) -> bool:
        """
        Carga un componente de custodio después de validar su hash
        
        Returns:
            True si el hash es válido, False si no coincide
        """
        computed_hash = CryptoEngine.hash_sha256(component)
        
        if computed_hash != verification_hash:
            return False
        
        # Buscar si ya existe y actualizar, o agregar nuevo
        existing = next((c for c in self.components if c.custodian_id == custodian_id), None)
        if existing:
            existing.key_component = component
            existing.verification_hash = verification_hash
        else:
            custodian = CustodianComponent(custodian_id, component, verification_hash)
            self.components.append(custodian)
        
        return True
    
    def reconstruct_master_key(self, components: List[CustodianComponent]) -> bool:
        """
        Reconstruye el master key a partir de 3 componentes de custodios
        
        Returns:
            True si se reconstruyó exitosamente
        """
        if len(components) != 3:
            raise ValueError("Exactly 3 custodian components required")
        
        # Validar todos los hashes
        for comp in components:
            if not comp.validate_hash():
                raise ValueError(f"Invalid hash for {comp.custodian_id}")
        
        # Reconstruir master key: MK = C1 ⊕ C2 ⊕ C3
        c1 = components[0].key_component
        c2 = components[1].key_component
        c3 = components[2].key_component
        
        self.master_key = CryptoEngine.xor_bytes(CryptoEngine.xor_bytes(c1, c2), c3)
        self.is_initialized = True
        
        return True
    
    def clear_master_key(self):
        """Limpia el master key de la memoria"""
        if self.master_key:
            # Sobrescribir con zeros antes de liberar
            self.master_key = bytes(32)
            self.master_key = None
        self.is_initialized = False
    
    def is_master_key_loaded(self) -> bool:
        """Verifica si el master key está cargado"""
        return self.is_initialized and self.master_key is not None
    
    def get_master_key(self) -> bytes:
        """Obtiene el master key (solo si está cargado)"""
        if not self.is_master_key_loaded():
            raise Exception("Master key not loaded")
        return self.master_key


class WorkingKeyStore:
    """Almacén de claves de trabajo encriptadas"""
    
    def __init__(self, master_key_manager: MasterKeyManager):
        self.keys: Dict[str, EncryptedKey] = {}
        self.master_key_manager = master_key_manager
    
    def generate_working_key(self, key_id: str, algorithm: str = "AES-256", 
                            purpose: str = "general") -> str:
        """
        Genera una nueva clave de trabajo y la encripta con el master key
        
        Returns:
            key_id de la clave generada
        """
        if not self.master_key_manager.is_master_key_loaded():
            raise Exception("Master key must be loaded before generating working keys")
        
        if key_id in self.keys:
            raise ValueError(f"Key '{key_id}' already exists")
        
        # Generar clave de trabajo
        working_key = CryptoEngine.generate_key(32)
        
        # Encriptar con master key
        master_key = self.master_key_manager.get_master_key()
        ciphertext, iv, tag = CryptoEngine.encrypt_aes_gcm(working_key, master_key)
        
        # Crear metadata
        metadata = KeyMetadata(key_id, algorithm, 256, purpose)
        
        # Almacenar clave encriptada
        encrypted_key = EncryptedKey(key_id, algorithm, ciphertext, iv, tag, metadata)
        self.keys[key_id] = encrypted_key
        
        # Limpiar clave de trabajo de memoria
        working_key = bytes(32)
        
        return key_id
    
    def get_working_key(self, key_id: str) -> bytes:
        """
        Obtiene una clave de trabajo desencriptada
        
        Returns:
            Clave de trabajo en bytes
        """
        if key_id not in self.keys:
            raise ValueError(f"Key '{key_id}' not found")
        
        encrypted_key = self.keys[key_id]
        master_key = self.master_key_manager.get_master_key()
        
        # Desencriptar clave de trabajo
        working_key = CryptoEngine.decrypt_aes_gcm(
            encrypted_key.encrypted_data,
            master_key,
            encrypted_key.iv,
            encrypted_key.tag
        )
        
        # Actualizar metadata
        encrypted_key.metadata.update_usage()
        
        return working_key
    
    def delete_working_key(self, key_id: str) -> bool:
        """Elimina una clave de trabajo del almacén"""
        if key_id in self.keys:
            del self.keys[key_id]
            return True
        return False
    
    def list_keys(self) -> List[Dict]:
        """Lista todas las claves almacenadas con su metadata"""
        return [
            {
                'key_id': key.key_id,
                'algorithm': key.algorithm,
                'metadata': key.metadata.to_dict()
            }
            for key in self.keys.values()
        ]
    
    def export_keys(self, filename: str):
        """Exporta todas las claves encriptadas a un archivo JSON"""
        data = {
            'keys': [key.to_dict() for key in self.keys.values()],
            'exported_at': datetime.now().isoformat()
        }
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)


class HSMSimulator:
    """Simulador principal del HSM"""
    
    def __init__(self, audit_log_file: str = "hsm_audit.log"):
        self.master_key_manager = MasterKeyManager()
        self.key_store = WorkingKeyStore(self.master_key_manager)
        self.crypto_engine = CryptoEngine()
        self.audit_logger = AuditLogger(audit_log_file)
    
    def initialize(self) -> List[CustodianComponent]:
        """
        Inicializa el HSM generando el master key y dividiéndolo
        
        Returns:
            Lista de componentes de custodios
        """
        components = self.master_key_manager.generate_master_key()
        self.audit_logger.log_operation(
            "HSM_INITIALIZATION",
            "Master key generated and split into 3 custodian components"
        )
        return components
    
    def load_custodians(self, custodian_data: List[Tuple[str, bytes, str]]) -> bool:
        """
        Carga los 3 componentes de custodios y reconstruye el master key
        
        Args:
            custodian_data: Lista de tuplas (custodian_id, component, hash)
        
        Returns:
            True si todos los componentes son válidos y el master key se reconstruyó
        """
        components = []
        
        for custodian_id, component, verification_hash in custodian_data:
            # Validar componente
            valid = self.master_key_manager.load_custodian_component(
                custodian_id, component, verification_hash
            )
            
            self.audit_logger.log_custodian_load(custodian_id, valid)
            
            if not valid:
                return False
            
            components.append(CustodianComponent(custodian_id, component, verification_hash))
        
        # Reconstruir master key
        try:
            self.master_key_manager.reconstruct_master_key(components)
            self.audit_logger.log_operation(
                "MASTER_KEY_LOAD",
                "Master key reconstructed from custodian components"
            )
            return True
        except Exception as e:
            self.audit_logger.log_operation(
                "MASTER_KEY_LOAD",
                f"Failed to reconstruct master key: {str(e)}",
                success=False
            )
            return False
    
    def generate_key(self, key_id: str, algorithm: str = "AES-256", 
                     purpose: str = "general") -> str:
        """Genera una nueva clave de trabajo"""
        try:
            result = self.key_store.generate_working_key(key_id, algorithm, purpose)
            self.audit_logger.log_key_generation(key_id)
            return result
        except Exception as e:
            self.audit_logger.log_operation(
                "KEY_GENERATION",
                f"Failed to generate key '{key_id}': {str(e)}",
                success=False
            )
            raise
    
    def encrypt(self, data: bytes, key_id: str, mode: str = "GCM") -> EncryptedData:
        """
        Encripta datos usando una clave de trabajo especificada
        
        Args:
            data: Datos a encriptar
            key_id: ID de la clave de trabajo a usar
            mode: Modo de encriptación (GCM por defecto)
        
        Returns:
            EncryptedData con el resultado
        """
        try:
            # Obtener clave de trabajo
            working_key = self.key_store.get_working_key(key_id)
            
            # Encriptar datos
            ciphertext, iv, tag = CryptoEngine.encrypt_aes_gcm(data, working_key)
            
            # Limpiar clave de memoria
            working_key = bytes(32)
            
            encrypted_data = EncryptedData(
                ciphertext=ciphertext,
                iv=iv,
                tag=tag,
                algorithm="AES-256",
                mode=mode,
                key_id=key_id
            )
            
            self.audit_logger.log_encryption(key_id, len(data))
            
            return encrypted_data
            
        except Exception as e:
            self.audit_logger.log_operation(
                "DATA_ENCRYPTION",
                f"Encryption failed with key '{key_id}': {str(e)}",
                success=False
            )
            raise
    
    def decrypt(self, encrypted_data: EncryptedData) -> bytes:
        """
        Desencripta datos usando la clave especificada en EncryptedData
        
        Args:
            encrypted_data: Objeto EncryptedData con los datos encriptados
        
        Returns:
            Datos desencriptados en bytes
        """
        try:
            # Obtener clave de trabajo
            working_key = self.key_store.get_working_key(encrypted_data.key_id)
            
            # Desencriptar datos
            plaintext = CryptoEngine.decrypt_aes_gcm(
                encrypted_data.ciphertext,
                working_key,
                encrypted_data.iv,
                encrypted_data.tag
            )
            
            # Limpiar clave de memoria
            working_key = bytes(32)
            
            self.audit_logger.log_decryption(
                encrypted_data.key_id,
                len(plaintext),
                success=True
            )
            
            return plaintext
            
        except Exception as e:
            self.audit_logger.log_decryption(
                encrypted_data.key_id,
                0,
                success=False
            )
            raise Exception(f"Decryption failed: {str(e)}")
    
    def get_status(self) -> Dict:
        """Obtiene el estado actual del HSM"""
        return {
            'master_key_loaded': self.master_key_manager.is_master_key_loaded(),
            'working_keys_count': len(self.key_store.keys),
            'system_health': 'operational' if self.master_key_manager.is_master_key_loaded() else 'standby'
        }
    
    def shutdown(self):
        """Apaga el HSM de forma segura limpiando claves de memoria"""
        self.master_key_manager.clear_master_key()
        self.audit_logger.log_operation("HSM_SHUTDOWN", "HSM shut down safely")


# Ejemplo de uso
if __name__ == "__main__":
    print("=" * 70)
    print("HSM SIMULATOR - DEMO")
    print("=" * 70)
    
    # 1. Inicializar HSM
    print("\n[1] Inicializando HSM...")
    hsm = HSMSimulator()
    custodians = hsm.initialize()
    
    print(f"✓ Master key generado y dividido en {len(custodians)} componentes")
    print("\nComponentes de Custodios:")
    for i, custodian in enumerate(custodians, 1):
        print(f"\n  Custodian {i}:")
        print(f"    ID: {custodian.custodian_id}")
        print(f"    Component: {custodian.key_component.hex()[:64]}...")
        print(f"    Hash: {custodian.verification_hash}")
    
    # 2. Cargar componentes de custodios
    print("\n\n[2] Cargando componentes de custodios...")
    custodian_data = [
        (c.custodian_id, c.key_component, c.verification_hash)
        for c in custodians
    ]
    
    success = hsm.load_custodians(custodian_data)
    if success:
        print("✓ Master key reconstruido exitosamente")
    else:
        print("✗ Error al reconstruir master key")
        exit(1)
    
    # 3. Generar claves de trabajo
    print("\n\n[3] Generando claves de trabajo...")
    hsm.generate_key("DATA-KEY-001", purpose="data encryption")
    hsm.generate_key("DATA-KEY-002", purpose="database encryption")
    print("✓ Claves de trabajo generadas")
    
    keys = hsm.key_store.list_keys()
    for key in keys:
        print(f"  - {key['key_id']}: {key['algorithm']}")
    
    # 4. Encriptar datos
    print("\n\n[4] Encriptando datos...")
    plaintext = b"Este es un mensaje secreto del HSM Simulator!"
    print(f"Texto plano: {plaintext.decode()}")
    
    encrypted = hsm.encrypt(plaintext, "DATA-KEY-001")
    print(f"✓ Datos encriptados")
    print(f"  Ciphertext: {encrypted.ciphertext.hex()[:64]}...")
    print(f"  IV: {encrypted.iv.hex()}")
    print(f"  Tag: {encrypted.tag.hex()}")
    
    # 5. Desencriptar datos
    print("\n\n[5] Desencriptando datos...")
    decrypted = hsm.decrypt(encrypted)
    print(f"✓ Datos desencriptados")
    print(f"Texto recuperado: {decrypted.decode()}")
    
    # 6. Verificar integridad
    print("\n\n[6] Verificando integridad...")
    if plaintext == decrypted:
        print("✓ Integridad verificada - Los datos coinciden perfectamente")
    else:
        print("✗ Error de integridad")
    
    # 7. Estado del HSM
    print("\n\n[7] Estado del HSM:")
    status = hsm.get_status()
    for key, value in status.items():
        print(f"  {key}: {value}")
    
    # 8. Log de auditoría
    print("\n\n[8] Log de Auditoría (últimas 5 entradas):")
    audit_trail = hsm.audit_logger.get_audit_trail()
    for entry in audit_trail[-5:]:
        print(f"  [{entry['timestamp']}] {entry['operation']}: {entry['details']}")
    
    print("\n" + "=" * 70)
    print("DEMO COMPLETADO")
    print("=" * 70)
