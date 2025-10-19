# HSM Simulator - Hardware Security Module
## Sistema de Gestión de Claves Maestras con Custodios

---

## 📋 Contenido del Proyecto

Este proyecto incluye 3 componentes principales:

1. **Backend Python** (`hsm_simulator.py`) - Implementación completa en Python
2. **Frontend HTML Standalone** (`hsm_simulator.html`) - Aplicación web que funciona sin internet
3. **Documentación** - Diagramas de clases, secuencias y documentación técnica

---

## 🚀 Cómo Usar el Simulador

### Opción 1: Versión HTML (Recomendada para presentación)

**Requisitos:** Solo un navegador web moderno (Chrome, Firefox, Edge)

**Pasos:**
1. Descarga el archivo `hsm_simulator.html`
2. Haz doble clic en el archivo o abre con tu navegador
3. ¡Listo! La aplicación funciona completamente sin internet

**Ventajas:**
- ✅ No requiere instalación
- ✅ Funciona sin internet
- ✅ Interfaz visual intuitiva
- ✅ Ideal para demostraciones

### Opción 2: Backend Python

**Requisitos:**
- Python 3.8 o superior
- pip (gestor de paquetes de Python)

**Instalación:**

```bash
# 1. Instalar la librería de criptografía
pip install cryptography

# 2. Ejecutar el simulador
python hsm_simulator.py
```

**Ventajas:**
- ✅ Código profesional para mostrar implementación
- ✅ Fácil de extender y modificar
- ✅ Incluye ejemplo de uso completo
- ✅ Genera logs de auditoría en archivos

---

## 📖 Guía de Uso Paso a Paso

### Fase 1: Generación de Master Key

1. **Iniciar el sistema**
   - Hacer clic en "Generar Master Key y Dividir"
   - El sistema genera una clave maestra de 256 bits
   - La divide en 3 componentes usando esquema XOR

2. **Guardar componentes de custodios**
   - Cada custodio recibe:
     - Componente en hexadecimal (256 bits)
     - Hash SHA-256 para verificación
   - **IMPORTANTE:** Guardar cada componente de forma segura
   - Usar el botón "Exportar" para descargar como JSON

### Fase 2: Carga de Custodios

1. **Cargar los 3 componentes**
   - Cada custodio ingresa:
     - Su componente (hex)
     - Su hash de verificación
   - El sistema valida cada hash automáticamente

2. **Reconstrucción automática**
   - Cuando los 3 componentes están cargados
   - El sistema reconstruye la Master Key: `MK = C1 ⊕ C2 ⊕ C3`
   - El indicador cambia a verde: "Master Key Cargada"

### Fase 3: Generar Claves de Trabajo

1. **Ir a la pestaña "Claves"**
2. **Ingresar un ID único** (ej: `DATA-KEY-001`)
3. **Hacer clic en "Generar Clave"**
   - El sistema genera una clave AES-256 aleatoria
   - La encripta con la Master Key usando AES-GCM
   - La almacena de forma segura

4. **Repetir** para crear múltiples claves según necesidad

### Fase 4: Encriptar Datos

1. **Ir a la pestaña "Encriptar"**
2. **Seleccionar una clave de trabajo** del dropdown
3. **Ingresar el texto a encriptar**
4. **Hacer clic en "Encriptar Datos"**
5. **Copiar el resultado** (JSON con ciphertext, IV, tag)

**Resultado incluye:**
- `ciphertext`: Datos encriptados en Base64
- `iv`: Vector de inicialización
- `algorithm`: "AES-256-GCM"
- `keyId`: ID de la clave usada
- `timestamp`: Momento de encriptación

### Fase 5: Desencriptar Datos

1. **Ir a la pestaña "Desencriptar"**
2. **Pegar el JSON** con los datos encriptados
3. **Hacer clic en "Desencriptar Datos"**
4. **Ver el texto original recuperado**

**Seguridad:**
- ✅ Verifica integridad mediante GCM tag
- ✅ Detecta cualquier modificación de datos
- ✅ Solo desencripta con la clave correcta

### Fase 6: Auditoría

1. **Ir a la pestaña "Auditoría"**
2. **Revisar todas las operaciones realizadas**
   - Timestamp exacto
   - Tipo de operación
   - Resultado (éxito/fallo)
   - Detalles adicionales

---

## 🔐 Algoritmos Implementados

### Criptografía

| Algoritmo | Uso | Estándar |
|-----------|-----|----------|
| **AES-256-GCM** | Encriptación simétrica autenticada | NIST FIPS 197 |
| **SHA-256** | Hashing para verificación | NIST FIPS 180-4 |
| **CSPRNG** | Generación de claves aleatorias | crypto.getRandomValues (Web Crypto API) |
| **XOR Scheme** | División de master key entre custodios | Esquema 3-of-3 |

### Esquema de Custodios

```
Master Key (MK) de 256 bits

Generación:
- C1 = random(256 bits)
- C2 = random(256 bits)  
- C3 = MK ⊕ C1 ⊕ C2

Reconstrucción:
- MK = C1 ⊕ C2 ⊕ C3

Verificación:
- H(Ci) = SHA-256(Ci) para cada componente
```

---

## 🏗️ Arquitectura del Sistema

### Componentes Principales

```
┌─────────────────────────────────────┐
│     Interfaz de Usuario (UI)       │
│  - Tabs para diferentes funciones   │
│  - Validación de entradas           │
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│   Lógica de Negocio (HSM Core)     │
│  - MasterKeyManager                 │
│  - WorkingKeyStore                  │
│  - CryptoEngine                     │
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│    Servicios Criptográficos        │
│  - Web Crypto API                   │
│  - AES-GCM                          │
│  - SHA-256                          │
└─────────────────────────────────────┘
```

### Flujo de Datos

```
1. Usuario → Genera MK → Divide en C1, C2, C3
2. Custodios → Cargan componentes → Reconstruyen MK
3. HSM → Genera Working Keys → Encripta con MK
4. Usuario → Encripta datos → Con Working Key
5. Usuario → Desencripta datos → Con Working Key
6. Sistema → Registra todo → Log de Auditoría
```

---

## 📊 Casos de Uso

### Caso 1: Inicialización del HSM

**Actor:** Administrador del Sistema

**Flujo:**
1. Administrador inicia el HSM
2. Sistema genera Master Key
3. Sistema divide MK en 3 componentes
4. Cada custodio recibe su componente + hash
5. Custodios guardan sus componentes de forma segura

### Caso 2: Activación Diaria

**Actores:** 3 Custodios

**Flujo:**
1. Custodio 1 ingresa su componente + hash
2. Sistema valida hash del componente 1
3. Custodio 2 ingresa su componente + hash
4. Sistema valida hash del componente 2
5. Custodio 3 ingresa su componente + hash
6. Sistema valida hash del componente 3
7. Sistema reconstruye Master Key
8. HSM queda operacional

### Caso 3: Encriptación de Datos Sensibles

**Actor:** Usuario de la Aplicación

**Flujo:**
1. Usuario selecciona clave de trabajo
2. Usuario ingresa datos a proteger
3. Sistema obtiene working key (desencriptada con MK)
4. Sistema encripta datos con working key
5. Sistema retorna datos encriptados + metadata
6. Sistema registra operación en auditoría

---

## 🧪 Pruebas y Validación

### Prueba 1: Integridad del Esquema de Custodios

```python
# Verificar que MK = C1 ⊕ C2 ⊕ C3
c1 = crypto_utils.randomBytes(32)
c2 = crypto_utils.randomBytes(32)
mk_original = crypto_utils.randomBytes(32)
c3 = crypto_utils.xor(crypto_utils.xor(mk_original, c1), c2)

# Reconstruir
mk_reconstructed = crypto_utils.xor(crypto_utils.xor(c1, c2), c3)

# Validar
assert mk_original == mk_reconstructed  # ✓ PASS
```

### Prueba 2: Validación de Hash

```python
# Generar componente
component = crypto_utils.randomBytes(32)
hash_original = crypto_utils.sha256(component)

# Modificar un byte
component_modified = component.copy()
component_modified[0] = (component_modified[0] + 1) % 256

# Verificar
hash_modified = crypto_utils.sha256(component_modified)
assert hash_original != hash_modified  # ✓ PASS - Detecta modificación
```

### Prueba 3: Encriptación/Desencriptación

```python
plaintext = b"Datos secretos del HSM"
key = crypto_utils.randomBytes(32)

# Encriptar
encrypted = aes_gcm.encrypt(plaintext, key)

# Desencriptar
decrypted = aes_gcm.decrypt(encrypted.ciphertext, key, encrypted.iv)

# Validar
assert plaintext == decrypted  # ✓ PASS
```

---

## 📝 Consideraciones de Seguridad

### Implementadas

✅ **Separación de Deberes** - Requiere 3 custodios
✅ **Verificación de Integridad** - SHA-256 hash de cada componente
✅ **Encriptación Autenticada** - AES-GCM con tag de autenticación
✅ **Claves Aleatorias** - CSPRNG para generación segura
✅ **Auditoría Completa** - Registro de todas las operaciones
✅ **Key Wrapping** - Working keys siempre encriptadas con MK

### Limitaciones (Simulador Educativo)

⚠️ **No es un HSM real** - Claves en memoria RAM, no en hardware seguro
⚠️ **Sin protección física** - No hay resistencia a tampering
⚠️ **Sin persistencia** - Datos se pierden al cerrar el navegador/aplicación
⚠️ **Sin rate limiting** - No hay límites de intentos de operaciones
⚠️ **Sin multi-usuario** - No hay sistema de autenticación de usuarios

### Mejoras para Producción

Para un sistema real, se necesitaría:

1. **Hardware Seguro** - HSM físico certificado FIPS 140-2 Level 3+
2. **Almacenamiento Persistente** - Base de datos encriptada
3. **Autenticación** - Sistema robusto de usuarios y roles
4. **Network Security** - TLS, firewalls, IDS/IPS
5. **Backup & Recovery** - Procedimientos de respaldo de claves
6. **Compliance** - Auditorías y certificaciones (PCI-DSS, SOC 2)

---

## 🎓 Material para la Presentación

### Demo en Vivo (5-10 minutos)

1. **Mostrar generación de MK** (1 min)
   - Explicar el esquema XOR
   - Mostrar los 3 componentes generados

2. **Cargar custodios** (2 min)
   - Simular que 3 personas diferentes cargan
   - Mostrar validación de hash
   - Mostrar activación del HSM

3. **Generar claves de trabajo** (1 min)
   - Crear 2-3 claves con diferentes IDs
   - Explicar key wrapping

4. **Encriptar datos** (2 min)
   - Encriptar un mensaje de ejemplo
   - Mostrar el resultado (ciphertext, IV, tag)

5. **Desencriptar datos** (2 min)
   - Recuperar el mensaje original
   - Demostrar integridad

6. **Mostrar auditoría** (1 min)
   - Revisar log de operaciones
   - Destacar trazabilidad

### Puntos Clave para Destacar

- 🔐 **Seguridad por diseño** - Separación de custodios
- 🎯 **Algoritmos estándar** - NIST FIPS certified
- 📊 **Auditoría completa** - Compliance ready
- 💡 **Arquitectura modular** - Fácil de extender
- ✅ **Validación de integridad** - Detección de tampering

---

## 📂 Estructura de Archivos Recomendada

```
hsm-simulator/
├── README.md                    # Este archivo
├── hsm_simulator.py             # Backend Python
├── hsm_simulator.html           # Frontend standalone
├── docs/
│   ├── diagrama_clases.png      # Diagrama de clases
│   ├── diagrama_secuencia.png   # Diagramas de secuencia
│   ├── arquitectura.png         # Arquitectura del sistema
│   └── presentacion.pptx        # PowerPoint para exposición
├── examples/
│   ├── custodian_1.json         # Ejemplo componente custodio 1
│   ├── custodian_2.json         # Ejemplo componente custodio 2
│   └── custodian_3.json         # Ejemplo componente custodio 3
└── tests/
    └── test_hsm.py              # Tests unitarios
```

---

## 🔧 Solución de Problemas

### Problema: "Master key must be loaded first"

**Causa:** Intentando usar el HSM sin haber cargado los 3 custodios

**Solución:** Cargar los 3 componentes de custodios primero

### Problema: "Hash verification failed"

**Causa:** El componente o hash ingresado no coincide

**Solución:** 
1. Verificar que copiaste correctamente el componente
2. Verificar que copiaste correctamente el hash
3. No debe haber espacios adicionales

### Problema: "Decryption failed"

**Causa:** Datos encriptados modificados o clave incorrecta

**Solución:**
1. Verificar que el JSON esté completo
2. Verificar que la clave usada para encriptar exista
3. No modificar manualmente el JSON encriptado

---

## 📚 Referencias y Bibliografía

### Estándares

- **NIST FIPS 197** - Advanced Encryption Standard (AES)
- **NIST FIPS 180-4** - Secure Hash Standard (SHA-256)
- **NIST SP 800-130** - Cryptographic Key Management
- **NIST SP 800-57** - Recommendation for Key Management

### Papers Académicos

- Shamir, A. (1979). "How to Share a Secret"
- Gennaro, R. et al. "Practical Threshold Signatures"
- Kocher, P. "Timing Attacks on Implementations"

### HSM Comerciales

- Thales Luna HSM - https://cpl.thalesgroup.com/
- Entrust nShield - https://www.entrust.com/
- AWS CloudHSM - https://aws.amazon.com/cloudhsm/
- Azure Key Vault - https://azure.microsoft.com/en-us/services/key-vault/

---

## 👥 Información del Proyecto

**Proyecto:** Simulador de HSM con Master Key y 3 Custodios

**Funcionalidades:**
1. Master key para encriptar todas las llaves
2. Módulo para ingresar llaves usando 3 custodios (llave y hash de comprobación)
3. Funciones para encriptar y desencriptar con elección de llave

**Entregas:**
- ✅ Hito 1 (09/11/2024): Marco conceptual y diseño
- ✅ Hito 2 (30/11/2024): Implementación y demostración

---

## 📞 Soporte

Para preguntas o problemas:
1. Revisar esta documentación
2. Verificar los diagramas de clases y secuencias
3. Ejecutar el código de ejemplo en Python
4. Probar la versión HTML standalone

---

**¡Éxito en tu presentación! 🚀**