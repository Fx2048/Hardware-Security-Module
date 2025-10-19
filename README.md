# Hardware-Security-Module

HITO 1: Marco Conceptual y Definición de Alcance
1.1 Valor para el Usuario
Un simulador de HSM proporciona:

Seguridad centralizada: Gestión unificada de claves criptográficas sin necesidad de hardware especializado costoso
Control de acceso robusto: Sistema de 3 custodios que implementa el principio de "separación de deberes"
Ambiente de desarrollo/pruebas: Permite desarrollar y probar aplicaciones criptográficas sin HSM físico (costos de $3,000-$50,000)
Educación y capacitación: Herramienta didáctica para comprender operaciones criptográficas empresariales
Cumplimiento normativo simulado: Práctica de estándares como PCI-DSS, FIPS 140-2

1.2 Funcionalidades de Sistemas HSM
Funcionalidades Core:

Generación de claves criptográficas seguras
Almacenamiento protegido de claves (master key y claves de trabajo)
Encriptación/desencriptación de datos
Gestión de ciclo de vida de claves
Control de acceso basado en roles (custodios)

Funcionalidades de Seguridad:

Key wrapping (encriptación de claves con master key)
Verificación de integridad mediante hash
Ceremonias de clave con múltiples custodios (n-of-m schemes)
Separación de funciones (dual control)
Auditoría de operaciones

1.3 Soluciones Comerciales y Open Source
Soluciones Comerciales:

Thales Luna HSM: Líder del mercado, FIPS 140-2 Level 3, desde $15,000
Entrust nShield: Para banca y PKI, $20,000-$50,000
Utimaco SecurityServer: Alto rendimiento, certificaciones gubernamentales
AWS CloudHSM: Servicio cloud, $1.45/hora (~$1,000/mes)
Azure Key Vault HSM: Managed service de Microsoft

Soluciones Open Source:

SoftHSM: Implementación software de PKCS#11, muy usado en testing
OpenDNSSEC: Incluye SoftHSM para signing de zonas DNS
PyKMIP: Protocolo Key Management Interoperability Protocol
Hashicorp Vault: Gestión de secretos con capacidades HSM-like

1.4 Investigación Académica
Áreas de Investigación Relevantes:

Criptografía de Umbral (Threshold Cryptography): Shamir's Secret Sharing (1979), permite dividir claves entre n custodios requiriendo m para reconstruir
Protocolos de Ceremonia de Claves: Investigación sobre procedimientos seguros para generación y carga de master keys
Análisis de Side-Channel Attacks: Estudios sobre vulnerabilidades físicas en HSMs (Kocher et al., timing attacks)
Post-Quantum Cryptography: Preparación de HSMs para resistir ataques cuánticos (NIST PQC standardization)
Cloud HSM Security: Investigación sobre HSMs virtualizados y multi-tenant

Papers Relevantes:

"How to Share a Secret" - Adi Shamir (1979)
"Cryptographic Key Management Architecture" - NIST SP 800-130
"Practical Threshold Signatures" - Gennaro et al.

1.5 Requisitos Funcionales
RF1 - Gestión de Master Key:

RF1.1: Generar master key aleatoria de 256 bits
RF1.2: Dividir master key entre 3 custodios mediante scheme 3-of-3
RF1.3: Reconstruir master key con componentes de 3 custodios
RF1.4: Verificar integridad de cada componente mediante hash SHA-256

RF2 - Gestión de Claves de Trabajo:

RF2.1: Generar claves de trabajo (AES-256)
RF2.2: Encriptar claves de trabajo con master key (key wrapping)
RF2.3: Almacenar claves encriptadas de forma persistente
RF2.4: Desencriptar claves de trabajo bajo demanda
RF2.5: Listar claves disponibles con metadatos

RF3 - Operaciones Criptográficas:

RF3.1: Encriptar datos con selección de clave
RF3.2: Desencriptar datos con la clave correspondiente
RF3.3: Soportar múltiples modos (AES-GCM, AES-CBC)
RF3.4: Validar tags de autenticación (GCM)

RF4 - Seguridad y Auditoría:

RF4.1: Registrar todas las operaciones con timestamp
RF4.2: Validar hash de verificación de custodios
RF4.3: Limpiar claves de memoria tras uso

1.6 Requisitos No Funcionales
RNF1 - Seguridad:

Uso de algoritmos estándar (AES-256, SHA-256)
No almacenar master key en texto plano
Limpieza segura de memoria (zeroing)
Resistencia a ataques de timing (operaciones de tiempo constante donde sea posible)

RNF2 - Rendimiento:

Encriptación/desencriptación < 100ms para mensajes < 1MB
Carga de custodios < 2 segundos

RNF3 - Usabilidad:

Interfaz gráfica intuitiva con flujos claros
Mensajes de error descriptivos
Visualización clara del estado del sistema

RNF4 - Mantenibilidad:

Código modular con separación de responsabilidades
Documentación inline del código
Manejo centralizado de excepciones

RNF5 - Portabilidad:

Multiplataforma (Windows, Linux, macOS)
Sin dependencias de hardware específico

1.7 Algoritmos a Utilizar
Algoritmos Criptográficos:

AES-256 (Advanced Encryption Standard)

Propósito: Encriptación simétrica de claves de trabajo y datos
Modo: AES-GCM (autenticado) como principal, CBC como alternativo
Justificación: Estándar NIST FIPS 197, ampliamente adoptado


SHA-256 (Secure Hash Algorithm)

Propósito: Hash de verificación de componentes de custodios
Justificación: NIST FIPS 180-4, resistente a colisiones


PBKDF2 (Password-Based Key Derivation Function 2)

Propósito: Derivar claves de componentes de custodios si se usa passwords
Parámetros: 100,000+ iteraciones
Justificación: NIST SP 800-132


XOR-based Secret Sharing (Alternativa simple a Shamir)

Propósito: Dividir master key entre custodios
Esquema: MK = C1 ⊕ C2 ⊕ C3
Justificación: Simple, seguro para scheme 3-of-3



Algoritmos de Apoyo:

HKDF (HMAC-based Key Derivation)

Propósito: Derivar claves específicas de contexto
Justificación: RFC 5869


CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)

Propósito: Generación de claves y IVs
Implementación: os.urandom() o secrets module en Python
