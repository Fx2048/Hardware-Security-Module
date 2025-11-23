"""
Modelos Pydantic para validación de requests/responses
"""

from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field


# ==================== CUSTODIAN / SETUP ====================

class CustodianComponentResponse(BaseModel):
    """Respuesta con un componente de custodio"""
    custodian_id: str
    key_component: str  # hex
    verification_hash: str
    created_at: str


class GenerateMasterKeyResponse(BaseModel):
    """Respuesta de generación de master key"""
    success: bool
    message: str
    components: List[CustodianComponentResponse]


class LoadCustodianRequest(BaseModel):
    """Request para cargar un componente de custodio"""
    custodian_id: str = Field(..., example="CUSTODIAN-1")
    component: str = Field(..., description="Component in hex format")
    verification_hash: str = Field(..., description="SHA-256 hash")


class LoadCustodianResponse(BaseModel):
    """Respuesta de carga de custodio"""
    success: bool
    message: str
    custodians_loaded: int
    master_key_ready: bool


# ==================== WORKING KEYS ====================

class GenerateKeyRequest(BaseModel):
    """Request para generar una clave de trabajo"""
    key_id: str = Field(..., min_length=1, max_length=50, example="DATA-KEY-001")


class KeyMetadataResponse(BaseModel):
    """Metadata de una clave"""
    key_id: str
    algorithm: str
    created_at: str
    last_used: Optional[str]
    usage_count: int


class WorkingKeyResponse(BaseModel):
    """Respuesta con información de clave de trabajo"""
    key_id: str
    algorithm: str = "AES-256"
    metadata: KeyMetadataResponse


class KeyListResponse(BaseModel):
    """Lista de claves de trabajo"""
    success: bool
    count: int
    keys: List[WorkingKeyResponse]


class DeleteKeyResponse(BaseModel):
    """Respuesta de eliminación de clave"""
    success: bool
    message: str


# ==================== ENCRYPTION/DECRYPTION ====================

class EncryptRequest(BaseModel):
    """Request para encriptar datos"""
    key_id: str = Field(..., example="DATA-KEY-001")
    plaintext: str = Field(..., description="Text to encrypt")


class EncryptResponse(BaseModel):
    """Respuesta con datos encriptados"""
    success: bool
    key_id: str
    ciphertext: str  # hex
    iv: str  # hex
    tag: str  # hex
    algorithm: str


class DecryptRequest(BaseModel):
    """Request para desencriptar datos"""
    key_id: str
    ciphertext: str  # hex
    iv: str  # hex
    tag: str  # hex


class DecryptResponse(BaseModel):
    """Respuesta con datos desencriptados"""
    success: bool
    plaintext: str


# ==================== AUDIT ====================

class AuditEntryResponse(BaseModel):
    """Entrada de auditoría"""
    timestamp: str
    operation: str
    details: str
    success: bool


class AuditLogResponse(BaseModel):
    """Log completo de auditoría"""
    success: bool
    count: int
    entries: List[AuditEntryResponse]


# ==================== STATUS ====================

class HSMStatusResponse(BaseModel):
    """Estado del HSM"""
    master_key_loaded: bool
    loaded_custodians: List[str]
    custodians_loaded: int
    custodians_required: int
    working_keys_count: int
    status: str  # 'operational' | 'standby'


class ErrorResponse(BaseModel):
    """Respuesta de error"""
    success: bool = False
    error: str
    detail: Optional[str] = None