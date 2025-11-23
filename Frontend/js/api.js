/**
 * Cliente API para comunicación con el backend FastAPI
 */

const API_BASE_URL = '/api';

class HSMApi {
    constructor(baseUrl = API_BASE_URL) {
        this.baseUrl = baseUrl;
    }

    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const config = {
            headers: { 'Content-Type': 'application/json' },
            ...options
        };

        try {
            const response = await fetch(url, config);
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.detail || 'API request failed');
            }
            
            return data;
        } catch (error) {
            console.error(`API Error [${endpoint}]:`, error);
            throw error;
        }
    }

    // ==================== SETUP ====================
    
    async generateMasterKey() {
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