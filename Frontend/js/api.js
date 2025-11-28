/**
 * Cliente API para comunicación con el backend FastAPI
 * Detecta automáticamente si está en local, ngrok o Render
 */

// Detectar entorno automáticamente
function getApiBaseUrl() {
    const hostname = window.location.hostname;
    
    console.log('🔍 Detectando entorno desde hostname:', hostname);
    
    // Producción en Render
    if (hostname.includes('onrender.com')) {
        console.log('✅ Modo: PRODUCCIÓN (Render)');
        return 'https://hardware-security-module-rd57.onrender.com/api';
    }
    
    // Desarrollo con ngrok
    if (hostname.includes('ngrok')) {
        console.log('✅ Modo: DESARROLLO (ngrok)');
        return 'https://hardware-security-module-rd57.onrender.com/api';
    }
    
    // Desarrollo local
    console.log('✅ Modo: LOCAL');
    return 'http://localhost:8000/api';
}

const API_BASE_URL = getApiBaseUrl();

console.log('🎯 API_BASE_URL final:', API_BASE_URL);
console.log('🧪 Probando conexión con backend...');

// Test de conexión al cargar
fetch(API_BASE_URL.replace('/api', '/'))
    .then(res => res.json())
    .then(data => {
        console.log('✅ Backend conectado:', data);
    })
    .catch(err => {
        console.error('❌ Backend NO conectado:', err);
        console.error('🔧 Verifica que la URL sea correcta:', API_BASE_URL);
    });

class HSMApi {
    constructor(baseUrl = API_BASE_URL) {
        this.baseUrl = baseUrl;
        console.log('✅ HSMApi inicializado con baseUrl:', this.baseUrl);
    }

    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        
        console.log('📡 Request:', {
            endpoint,
            url,
            method: options.method || 'GET'
        });
        
        const config = {
            headers: { 'Content-Type': 'application/json' },
            ...options
        };

        try {
            const response = await fetch(url, config);
            
            console.log(`📥 Response: ${response.status} ${response.statusText}`);
            
            // Si es 404, el endpoint no existe
            if (response.status === 404) {
                const text = await response.text();
                console.error('❌ Endpoint no encontrado (404):', url);
                console.error('📄 Respuesta del servidor:', text);
                throw new Error(`Endpoint not found: ${endpoint}`);
            }
            
            // Intentar parsear JSON
            let data;
            const contentType = response.headers.get('content-type');
            
            if (contentType && contentType.includes('application/json')) {
                data = await response.json();
            } else {
                const text = await response.text();
                console.error('❌ Respuesta no es JSON:', text);
                throw new Error(`Server returned non-JSON response: ${text}`);
            }
            
            if (!response.ok) {
                console.error('❌ Error en respuesta:', data);
                throw new Error(data.detail || 'API request failed');
            }
            
            console.log('✅ Datos recibidos:', data);
            return data;
        } catch (error) {
            console.error(`❌ API Error [${endpoint}]:`, error);
            throw error;
        }
    }

    // ==================== SETUP ====================
    
    async generateMasterKey() {
        console.log('🔑 Llamando a generateMasterKey()');
        return this.request('/setup/generate', { method: 'POST' });
    }

    async loadCustodian(custodianId, component, verificationHash) {
        return this.request('/setup/load-custodian', {
            method: 'POST',
            body: JSON.stringify({
                custodian_id: custodianId,
                component: component,
                verification_hash: verificationHash
            })
        });
    }

    async resetHSM() {
        return this.request('/setup/reset', { method: 'POST' });
    }

    // ==================== KEYS ====================

    async generateWorkingKey(keyId) {
        return this.request('/keys/generate', {
            method: 'POST',
            body: JSON.stringify({ key_id: keyId })
        });
    }

    async listWorkingKeys() {
        return this.request('/keys/list', { method: 'GET' });
    }

    async deleteWorkingKey(keyId) {
        return this.request(`/keys/${encodeURIComponent(keyId)}`, { 
            method: 'DELETE' 
        });
    }

    // ==================== CRYPTO ====================

    async encrypt(keyId, plaintext) {
        return this.request('/crypto/encrypt', {
            method: 'POST',
            body: JSON.stringify({ key_id: keyId, plaintext })
        });
    }

    async decrypt(keyId, ciphertext, iv, tag) {
        return this.request('/crypto/decrypt', {
            method: 'POST',
            body: JSON.stringify({ key_id: keyId, ciphertext, iv, tag })
        });
    }

    // ==================== AUDIT ====================

    async getAuditLog(limit = 100) {
        return this.request(`/audit/log?limit=${limit}`, { method: 'GET' });
    }

    async clearAuditLog() {
        return this.request('/audit/clear', { method: 'DELETE' });
    }

    // ==================== STATUS ====================

    async getStatus() {
        return this.request('/status/', { method: 'GET' });
    }
}

// Exportar instancia global
const api = new HSMApi();

console.log('🎯 api.baseUrl final:', api.baseUrl);
console.log('✅ HSM API Client listo para usar');