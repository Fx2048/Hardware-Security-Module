/**
 * Funciones de interfaz de usuario
 */

// ==================== NOTIFICACIONES ====================

function showNotification(message, type = 'info') {
    const area = document.getElementById('notificationArea');
    const icon = type === 'success' ? '✓' : type === 'error' ? '✗' : 'ℹ';
    
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `<span>${icon}</span><span>${message}</span>`;
    area.appendChild(notification);

    setTimeout(() => notification.remove(), 5000);
}

// ==================== TABS ====================

function switchTab(tabName) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    event.target.classList.add('active');
    
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.getElementById(tabName + 'Tab').classList.add('active');
}

// ==================== STATUS ====================

function updateStatusUI(status) {
    const indicator = document.getElementById('statusIndicator');
    const text = document.getElementById('statusText');

    if (status.master_key_loaded) {
        indicator.className = 'status-indicator status-loaded';
        text.textContent = 'Master Key Cargada';
    } else {
        indicator.className = 'status-indicator status-unloaded';
        text.textContent = `Master Key No Cargada (${status.custodians_loaded}/3)`;
    }
}

// ==================== CUSTODIAN COMPONENTS ====================

function displayCustodianComponents(components) {
    const card = document.getElementById('custodianComponentsCard');
    const container = document.getElementById('custodianComponents');

    container.innerHTML = components.map((comp, idx) => `
        <div class="custodian-box">
            <div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:15px">
                <h4>${comp.custodian_id}</h4>
                <button class="btn btn-primary btn-sm" onclick="exportComponent(${idx})">
                    💾 Exportar
                </button>
            </div>
            <div class="form-group">
                <label>Componente (Hex):</label>
                <div class="code-box green">${comp.key_component}</div>
            </div>
            <div class="form-group">
                <label>Hash de Verificación (SHA-256):</label>
                <div class="code-box cyan">${comp.verification_hash}</div>
            </div>
        </div>
    `).join('');

    card.style.display = 'block';
}

function updateCustodianStatus(index, loaded) {
    const status = document.getElementById(`status${index}`);
    if (status) {
        status.style.display = loaded ? 'block' : 'none';
    }
}

function resetCustodianUI() {
    // Limpiar UI de custodios
    for (let i = 0; i < 3; i++) {
        document.getElementById(`component${i}`).value = '';
        document.getElementById(`hash${i}`).value = '';
        updateCustodianStatus(i, false);
    }
    
    // Resetear estado
    appState.loadedCustodians = [false, false, false];
    appState.custodianComponents = [];
    
    // Ocultar componentes generados
    document.getElementById('custodianComponentsCard').style.display = 'none';
    
    // Mostrar notificación
    showNotification('HSM reiniciado - Requiere custodios nuevamente', 'info');
}

// ==================== WORKING KEYS LIST ====================

function updateWorkingKeysList(keys) {
    const container = document.getElementById('workingKeysContainer');
    document.getElementById('keyCount').textContent = keys.length;

    if (keys.length === 0) {
        container.innerHTML = '<div class="empty-state">No hay claves de trabajo generadas aún</div>';
        return;
    }

    container.innerHTML = keys.map(key => `
        <div class="key-item">
            <div class="key-info">
                <div class="key-id">${key.key_id}</div>
                <div class="key-details">
                    ${key.algorithm} • ${new Date(key.metadata.created_at).toLocaleString()}
                    ${key.metadata.usage_count > 0 ? `• Usado ${key.metadata.usage_count} veces` : ''}
                </div>
            </div>
            <button class="btn btn-danger btn-sm" onclick="deleteWorkingKey('${key.key_id}')">
                🗑️ Eliminar
            </button>
        </div>
    `).join('');
}

function updateKeySelects(keys) {
    const select = document.getElementById('encryptKeySelect');
    
    select.innerHTML = '<option value="">-- Seleccione una clave --</option>' +
        keys.map(key => `<option value="${key.key_id}">${key.key_id}</option>`).join('');
}

// ==================== AUDIT LOG ====================

function updateAuditLog(entries) {
    const container = document.getElementById('auditLogContainer');
    
    if (entries.length === 0) {
        container.innerHTML = '<div class="empty-state">No hay operaciones registradas aún</div>';
        return;
    }

    container.innerHTML = entries.map(entry => `
        <div class="audit-entry ${entry.success ? 'success' : 'error'}">
            <div class="audit-header">
                <span class="audit-operation">${entry.operation}</span>
                <span class="audit-time">${new Date(entry.timestamp).toLocaleString()}</span>
            </div>
            <div class="audit-details">${entry.details}</div>
        </div>
    `).join('');
}

// ==================== ENCRYPTION RESULTS ====================

function showEncryptedResult(result) {
    const output = {
        keyId: result.key_id,
        ciphertext: result.ciphertext,
        iv: result.iv,
        tag: result.tag,
        algorithm: result.algorithm
    };
    
    document.getElementById('encryptedOutput').textContent = JSON.stringify(output, null, 2);
    document.getElementById('encryptedResultCard').style.display = 'block';
}

function showDecryptedResult(plaintext) {
    document.getElementById('decryptedOutput').textContent = plaintext;
    document.getElementById('decryptedResultCard').style.display = 'block';
}

// ==================== CLIPBOARD ====================

function copyToClipboard(elementId) {
    const text = document.getElementById(elementId).textContent;
    navigator.clipboard.writeText(text).then(() => {
        showNotification('Copiado al portapapeles', 'success');
    }).catch(err => {
        showNotification('Error al copiar: ' + err.message, 'error');
    });
}