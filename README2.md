┌─────────────────────────────────────────────┐
│         Capa de Presentación (UI)           │
│  - Interfaz gráfica (Tkinter/React)         │
│  - Validación de entrada                    │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│        Capa de Lógica de Negocio            │
│  - HSMController                            │
│  - CustodianManager                         │
│  - CryptoOperations                         │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│          Capa de Servicios                  │
│  - KeyManagementService                     │
│  - EncryptionService                        │
│  - AuditService                             │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│         Capa de Persistencia                │
│  - KeyStore (JSON/SQLite)                   │
│  - AuditLog                                 │
└─────────────────────────────────────────────┘
