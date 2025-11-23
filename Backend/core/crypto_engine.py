"""
Motor criptográfico para operaciones de encriptación/desencriptación
Implementa AES-256-GCM, SHA-256 y operaciones XOR
"""

import hashlib
import secrets
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoEngine:
    """Motor criptográfico para el HSM"""
    
    KEY_SIZE = 32  # 256 bits
    IV_SIZE = 12   # 96 bits para GCM
    TAG_SIZE = 16  # 128 bits
    
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
    def xor_bytes(a: bytes, b: bytes) -> bytes:
        """XOR entre dos arrays de bytes"""
        if len(a) != len(b):
            raise ValueError("Byte arrays must be same length for XOR")
        return bytes(x ^ y for x, y in zip(a, b))
    
    @staticmethod
    def encrypt_aes_gcm(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encripta datos usando AES-256-GCM
        
        Args:
            plaintext: Datos a encriptar
            key: Clave de 32 bytes
            
        Returns:
            Tuple[ciphertext, iv, tag]
        """
        if len(key) != CryptoEngine.KEY_SIZE:
            raise ValueError(f"Key must be {CryptoEngine.KEY_SIZE} bytes for AES-256")
        
        iv = CryptoEngine.generate_iv()
        aesgcm = AESGCM(key)
        
        # AES-GCM devuelve ciphertext con tag incluido al final
        ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)
        
        # Separar ciphertext y tag (últimos 16 bytes son el tag)
        ciphertext = ciphertext_with_tag[:-CryptoEngine.TAG_SIZE]
        tag = ciphertext_with_tag[-CryptoEngine.TAG_SIZE:]
        
        return ciphertext, iv, tag
    
    @staticmethod
    def decrypt_aes_gcm(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
        """
        Desencripta datos usando AES-256-GCM
        
        Args:
            ciphertext: Datos encriptados
            key: Clave de 32 bytes
            iv: Vector de inicialización
            tag: Tag de autenticación
            
        Returns:
            Datos desencriptados
            
        Raises:
            Exception: Si la autenticación falla
        """
        if len(key) != CryptoEngine.KEY_SIZE:
            raise ValueError(f"Key must be {CryptoEngine.KEY_SIZE} bytes for AES-256")
        
        aesgcm = AESGCM(key)
        ciphertext_with_tag = ciphertext + tag
        
        try:
            return aesgcm.decrypt(iv, ciphertext_with_tag, None)
        except Exception as e:
            raise Exception(f"Decryption failed - data may be corrupted: {str(e)}")