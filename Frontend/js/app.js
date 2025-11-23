/**
 * Aplicación principal - Lógica de negocio y estado
 */

// Estado global
const appState = {
    custodianComponents: [],
    loadedCustodians: [false, false, false]
};

// ==================== INICIALIZACIÓN ====================

async function initializeApp() {
    try {
        await refreshStatus();
        await refreshWorkingKeys();
        await refreshAuditLog();
        
        
    } catch (error) {
        console.error('Error initializing app:', error);
        showNotification('Error conectando con el servidor', 'error');
    }
}


async function refreshStatus() {
    try {
        const status = await api.getStatus();
        updateStatusUI(status);
        
        // Verificar si la sesión expiró
        if (status.inactivity_seconds !== undefined && 
            status.timeout_remaining !== undefined &&
            status.timeout_remaining <= 0) {
            
            showNotification('Sesión expirada por inactividad', 'warning');
            resetCustodianUI();
        }
        
        // Actualizar indicadores de custodios cargados
        for (let i = 0; i < 3; i++) {
            const custodianId = `CUSTODIAN-${i + 1}`;
            const isLoaded = status.loaded_custodians.includes(custodianId);
            appState.loadedCustodians[i] = isLoaded;
            updateCustodianStatus(i, isLoaded);
        }
    } catch (error) {
        console.error('Error fetching status:', error);
        // Si hay error de conexión, asumir sesión expirada
        if (error.message.includes('expired') || error.message.includes('inactivity')) {
            resetCustodianUI();
        }
    }
}

async function refreshWorkingKeys() {
    try {
        const result = await api.listWorkingKeys();
        updateWorkingKeysList(result.keys);
        updateKeySelects(result.keys);
    } catch (error) {
        console.error('Error fetching keys:', error);
    }
}

async function refreshAuditLog() {
    try {
        const result = await api.getAuditLog(100);
        updateAuditLog(result.entries);
    } catch (error) {
        console.error('Error fetching audit log:', error);
    }
}

// ==================== MASTER KEY ====================

async function generateMasterKey() {
    try {
        const result = await api.generateMasterKey();
        
        appState.custodianComponents = result.components;
        appState.loadedCustodians = [false, false, false];
        
        displayCustodianComponents(result.components);
        
        // Limpiar inputs de custodios
        for (let i = 0; i < 3; i++) {
            document.getElementById(`component${i}`).value = '';
            document.getElementById(`hash${i}`).value = '';
            updateCustodianStatus(i, false);
        }
        
        await refreshStatus();
        await refreshAuditLog();
        
        showNotification('Master key generada y dividida exitosamente', 'success');
    } catch (error) {
        showNotification('Error al generar master key: ' + error.message, 'error');
    }
}

function exportComponent(index) {
    const comp = appState.custodianComponents[index];
    if (!comp) {
        showNotification('Componente no disponible', 'error');
        return;
    }
    
    const dataStr = JSON.stringify({
        custodian_id: comp.custodian_id,
        key_component: comp.key_component,
        verification_hash: comp.verification_hash
    }, null, 2);
    
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${comp.custodian_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
    
    showNotification(`Componente ${comp.custodian_id} exportado`, 'success');
}

// ==================== CUSTODIAN LOADING ====================

async function loadCustodian(index) {
    const component = document.getElementById(`component${index}`).value.trim();
    const hash = document.getElementById(`hash${index}`).value.trim();
    const custodianId = `CUSTODIAN-${index + 1}`;

    if (!component || !hash) {
        showNotification('Por favor ingrese el componente y el hash', 'error');
        return;
    }

    try {
        const result = await api.loadCustodian(custodianId, component, hash);
        
        appState.loadedCustodians[index] = true;
        updateCustodianStatus(index, true);
        
        await refreshStatus();
        await refreshAuditLog();
        
        if (result.master_key_ready) {
            showNotification('¡Master key cargada exitosamente! HSM operacional', 'success');
        } else {
            showNotification(`Custodio ${index + 1} cargado (${result.custodians_loaded}/3)`, 'success');
        }
    } catch (error) {
        showNotification(`Error: ${error.message}`, 'error');
    }
}

// ==================== WORKING KEYS ====================

async function generateWorkingKey() {
    const keyId = document.getElementById('newKeyId').value.trim();

    if (!keyId) {
        showNotification('Por favor ingrese un ID de clave', 'error');
        return;
    }

    try {
        await api.generateWorkingKey(keyId);
        
        document.getElementById('newKeyId').value = '';
        
        await refreshWorkingKeys();
        await refreshAuditLog();
        
        showNotification(`Clave de trabajo ${keyId} generada exitosamente`, 'success');
    } catch (error) {
        showNotification('Error: ' + error.message, 'error');
    }
}

async function deleteWorkingKey(keyId) {
    try {
        await api.deleteWorkingKey(keyId);
        
        await refreshWorkingKeys();
        await refreshAuditLog();
        
        showNotification(`Clave ${keyId} eliminada`, 'info');
    } catch (error) {
        showNotification('Error: ' + error.message, 'error');
    }
}

// ==================== ENCRYPTION/DECRYPTION ====================

async function encryptData() {
    const keyId = document.getElementById('encryptKeySelect').value;
    const plaintext = document.getElementById('plaintextInput').value;

    if (!keyId) {
        showNotification('Por favor seleccione una clave de trabajo', 'error');
        return;
    }

    if (!plaintext) {
        showNotification('Por favor ingrese datos para encriptar', 'error');
        return;
    }

    try {
        const result = await api.encrypt(keyId, plaintext);
        
        showEncryptedResult(result);
        await refreshAuditLog();
        
        showNotification('Datos encriptados exitosamente', 'success');
    } catch (error) {
        showNotification('Error: ' + error.message, 'error');
    }
}

async function decryptData() {
    const encryptedInput = document.getElementById('encryptedInput').value.trim();

    if (!encryptedInput) {
        showNotification('Por favor proporcione datos encriptados', 'error');
        return;
    }

    try {
        const encData = JSON.parse(encryptedInput);
        
        const result = await api.decrypt(
            encData.keyId,
            encData.ciphertext,
            encData.iv,
            encData.tag
        );
        
        showDecryptedResult(result.plaintext);
        await refreshAuditLog();
        
        showNotification('Datos desencriptados exitosamente', 'success');
    } catch (error) {
        if (error instanceof SyntaxError) {
            showNotification('JSON inválido', 'error');
        } else {
            showNotification('Error: ' + error.message, 'error');
        }
    }
}

// Inicializar al cargar la página
document.addEventListener('DOMContentLoaded', initializeApp);