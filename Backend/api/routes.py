"""
Endpoints de la API REST para el HSM Simulator
"""

from fastapi import APIRouter, HTTPException

from typing import List


from models.schemas import (
    GenerateMasterKeyResponse, CustodianComponentResponse,
    LoadCustodianRequest, LoadCustodianResponse,
    GenerateKeyRequest, KeyListResponse, WorkingKeyResponse, 
    KeyMetadataResponse, DeleteKeyResponse,
    EncryptRequest, EncryptResponse,
    DecryptRequest, DecryptResponse,
    AuditLogResponse, AuditEntryResponse,
    HSMStatusResponse, ErrorResponse
)
from core.hsm_simulator import HSMSimulator, EncryptedData
from services.audit_logger import audit_logger


hsm = HSMSimulator()

# Routers por dominio
setup_router = APIRouter(prefix="/setup", tags=["Setup & Custodians"])
keys_router = APIRouter(prefix="/keys", tags=["Working Keys"])
crypto_router = APIRouter(prefix="/crypto", tags=["Encryption/Decryption"])
audit_router = APIRouter(prefix="/audit", tags=["Audit Log"])
status_router = APIRouter(prefix="/status", tags=["Status"])


# Endpoints
@setup_router.post("/generate", response_model=GenerateMasterKeyResponse)
async def generate_master_key():
    """Genera un nuevo master key y lo divide en 3 componentes de custodios"""
    try:
        components = hsm.generate_master_key()
        audit_logger.log_master_key_generated()
        
        return GenerateMasterKeyResponse(
            success=True,
            message="Master key generated and split into 3 custodian components",
            components=[CustodianComponentResponse(**c) for c in components]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@setup_router.post("/load-custodian", response_model=LoadCustodianResponse)
async def load_custodian(request: LoadCustodianRequest):
    """Carga un componente de custodio para reconstruir el master key"""
    success, message = hsm.load_custodian(
        request.custodian_id,
        request.component,
        request.verification_hash
    )
    
    audit_logger.log_custodian_load(request.custodian_id, success)
    
    if hsm.master_key_manager.is_loaded:
        audit_logger.log_master_key_reconstructed()
    
    if not success:
        raise HTTPException(status_code=400, detail=message)
    
    return LoadCustodianResponse(
        success=True,
        message=message,
        custodians_loaded=hsm.master_key_manager.get_loaded_count(),
        master_key_ready=hsm.master_key_manager.is_loaded
    )


@setup_router.post("/reset")
async def reset_hsm():
    """Reinicia el HSM completamente (limpia master key y claves)"""
    hsm.reset()
    audit_logger.log_hsm_reset()
    return {"success": True, "message": "HSM reset successfully"}


# Endpoints llaves

@keys_router.post("/generate", response_model=WorkingKeyResponse)
async def generate_working_key(request: GenerateKeyRequest):
    """Genera una nueva clave de trabajo encriptada con el master key"""
    if not hsm.master_key_manager.is_loaded:
        raise HTTPException(status_code=400, detail="Master key not loaded")
    
    try:
        key_data = hsm.generate_working_key(request.key_id)
        audit_logger.log_key_generation(request.key_id)
        
        return WorkingKeyResponse(
            key_id=key_data['key_id'],
            algorithm="AES-256",
            metadata=KeyMetadataResponse(**key_data['metadata'])
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@keys_router.get("/list", response_model=KeyListResponse)
async def list_working_keys():
    """Lista todas las claves de trabajo"""
    keys = hsm.list_working_keys()
    
    return KeyListResponse(
        success=True,
        count=len(keys),
        keys=[
            WorkingKeyResponse(
                key_id=k['key_id'],
                algorithm="AES-256",
                metadata=KeyMetadataResponse(**k['metadata'])
            ) for k in keys
        ]
    )


@keys_router.delete("/{key_id}", response_model=DeleteKeyResponse)
async def delete_working_key(key_id: str):
    """Elimina una clave de trabajo"""
    success = hsm.delete_working_key(key_id)
    
    if success:
        audit_logger.log_key_deletion(key_id)
        return DeleteKeyResponse(success=True, message=f"Key '{key_id}' deleted")
    else:
        raise HTTPException(status_code=404, detail=f"Key '{key_id}' not found")


# Endpoints encriptacion

@crypto_router.post("/encrypt", response_model=EncryptResponse)
async def encrypt_data(request: EncryptRequest):
    """Encripta datos usando una clave de trabajo"""
    if not hsm.master_key_manager.is_loaded:
        raise HTTPException(status_code=400, detail="Master key not loaded")
    
    try:
        plaintext_bytes = request.plaintext.encode('utf-8')
        encrypted = hsm.encrypt(plaintext_bytes, request.key_id)
        
        audit_logger.log_encryption(request.key_id, len(plaintext_bytes))
        
        return EncryptResponse(
            success=True,
            key_id=encrypted.key_id,
            ciphertext=encrypted.ciphertext.hex(),
            iv=encrypted.iv.hex(),
            tag=encrypted.tag.hex(),
            algorithm=encrypted.algorithm
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@crypto_router.post("/decrypt", response_model=DecryptResponse)
async def decrypt_data(request: DecryptRequest):
    """Desencripta datos usando una clave de trabajo"""
    if not hsm.master_key_manager.is_loaded:
        raise HTTPException(status_code=400, detail="Master key not loaded")
    
    try:
        encrypted_data = EncryptedData(
            ciphertext=bytes.fromhex(request.ciphertext),
            iv=bytes.fromhex(request.iv),
            tag=bytes.fromhex(request.tag),
            key_id=request.key_id
        )
        
        plaintext_bytes = hsm.decrypt(encrypted_data)
        audit_logger.log_decryption(request.key_id, success=True)
        
        return DecryptResponse(
            success=True,
            plaintext=plaintext_bytes.decode('utf-8')
        )
    except ValueError as e:
        audit_logger.log_decryption(request.key_id, success=False)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        audit_logger.log_decryption(request.key_id, success=False)
        raise HTTPException(status_code=500, detail=str(e))


# Endpoints audiciones

@audit_router.get("/log", response_model=AuditLogResponse)
async def get_audit_log(limit: int = 100):
    """Obtiene el log de auditoría"""
    entries = audit_logger.get_entries(limit)
    
    return AuditLogResponse(
        success=True,
        count=len(entries),
        entries=[AuditEntryResponse(**e) for e in entries]
    )


@audit_router.get("/key/{key_id}")
async def get_key_audit_history(key_id: str):
    """Obtiene el historial de auditoría de una clave específica"""
    entries = audit_logger.get_by_key(key_id)
    return {
        "success": True,
        "key_id": key_id,
        "count": len(entries),
        "entries": entries
    }


@audit_router.get("/failures")
async def get_audit_failures(limit: int = 50):
    """Obtiene las operaciones fallidas"""
    entries = audit_logger.get_failures(limit)
    return {
        "success": True,
        "count": len(entries),
        "entries": entries
    }


@audit_router.get("/stats")
async def get_audit_stats():
    """Obtiene estadísticas del log de auditoría"""
    stats = audit_logger.get_stats()
    return {
        "success": True,
        "stats": stats
    }


@audit_router.delete("/clear")
async def clear_audit_log():
    """Limpia el log de auditoría"""
    audit_logger.clear()
    return {"success": True, "message": "Audit log cleared"}


# Endpoints estado

@status_router.get("/", response_model=HSMStatusResponse)
async def get_status():
    """Obtiene el estado actual del HSM"""
    return HSMStatusResponse(**hsm.get_status())