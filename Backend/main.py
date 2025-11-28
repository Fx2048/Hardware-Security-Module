"""
HSM Simulator - FastAPI Application
Punto de entrada principal de la API con base de datos
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from contextlib import asynccontextmanager

from api.routes import (
    setup_router, 
    keys_router, 
    crypto_router, 
    audit_router, 
    status_router
)
from core.hsm_simulator import HSMSimulator
from database.connection import init_database


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager para startup/shutdown"""
    # Startup - Inicializar base de datos
    print("🔒 HSM Simulator starting...")
    init_database()
    print("✓ Database ready")
    yield
    # Shutdown
    print("🔒 HSM Simulator shutting down...")


app = FastAPI(
    title="HSM Simulator API",
    description="""
    Hardware Security Module Simulator - Sistema de Gestión de Claves Maestras
    
    ## Funcionalidades
    
    * **Setup**: Generación y carga de master key con custodios
    * **Keys**: Gestión de claves de trabajo (generación, listado, eliminación)
    * **Crypto**: Operaciones de encriptación y desencriptación AES-256-GCM
    * **Audit**: Registro de auditoría persistente de todas las operaciones
    * **Status**: Estado del HSM
    
    ## Base de Datos
    
    Este simulador utiliza SQLite para persistir:
    - Claves de trabajo (encriptadas con master key)
    - Log de auditoría completo
    - Configuración del HSM
    
    **NOTA**: El master key NUNCA se almacena - solo existe en memoria mientras el HSM está activo.
    
    ## Flujo de uso
    
    1. Generar master key (se divide en 3 componentes)
    2. Cargar los 3 componentes de custodios
    3. Generar claves de trabajo (se persisten encriptadas)
    4. Usar claves para encriptar/desencriptar datos
    """,
    version="1.1.0",
    lifespan=lifespan
)

# ==================== CORS - MUY PERMISIVO ====================
# ⚠️ IMPORTANTE: Esto debe ir ANTES de registrar los routers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ← Permite TODOS los orígenes
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Registrar routers
app.include_router(setup_router, prefix="/api")
app.include_router(keys_router, prefix="/api")
app.include_router(crypto_router, prefix="/api")
app.include_router(audit_router, prefix="/api")
app.include_router(status_router, prefix="/api")


@app.get("/", tags=["Root"])
async def root():
    """Endpoint raíz con información de la API"""
    return {
        "name": "HSM Simulator API",
        "version": "1.1.0",
        "status": "running",
        "database": "SQLite",
        "docs": "/docs",
        "endpoints": {
            "setup": "/api/setup",
            "keys": "/api/keys",
            "crypto": "/api/crypto",
            "audit": "/api/audit",
            "status": "/api/status"
        }
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint"""
    from database.connection import get_db
    
    try:
        with get_db() as conn:
            conn.execute("SELECT 1")
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    return {
        "status": "healthy",
        "database": db_status
    }