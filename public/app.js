// MServer - Multi-Server Frontend Application

// Note: CSRF token management is in utils.js (window.csrfToken and fetchCSRFToken)

// Utility: promise-based sleep
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

// ==================== Helpers ====================

/**
 * Poll until a server's status is 'stopped' or until timeoutMs elapses.
 * Returns true if the server stopped, false on timeout.
 */
async function waitForServerStopped(serverId, timeoutMs = 40000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const serverList = await apiRequest('/api/servers');
      const s = serverList.servers.find(sv => sv.id === serverId);
      if (!s || s.status === 'stopped') return true;
    } catch (_) {}
    await sleep(2000);
  }
  return false;
}

// Global fetch wrapper to handle authentication errors and CSRF tokens
// Store original fetch for utils.js to use when fetching CSRF token
window.originalFetch = window.fetch;
const originalFetch = window.fetch;
window.fetch = async function(...args) {
  // Ensure options object exists before mutating
  if (!args[1]) args[1] = {};

  // Add CSRF token to state-changing requests
  const method = args[1]?.method?.toUpperCase();
  if (method && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
    if (!args[1].headers) {
      args[1].headers = {};
    }
    if (window.csrfToken && !args[1].headers['X-CSRF-Token']) {
      args[1].headers['X-CSRF-Token'] = window.csrfToken;
    }
  }

  let response = await originalFetch.apply(this, args);

  // If CSRF token expired/invalid, refresh and retry once
  if (response.status === 403) {
    const clone = response.clone();
    try {
      const data = await clone.json();
      if (data.error && data.error.includes('CSRF')) {
        await fetchCSRFToken();
        if (args[1].headers) {
          args[1].headers['X-CSRF-Token'] = window.csrfToken;
        }
        response = await originalFetch.apply(this, args);
      }
    } catch (_) { /* not JSON — leave original 403 response */ }
  }

  // Redirect to login if authentication fails (except for auth endpoints)
  if (response.status === 401 && !args[0].includes('/api/auth/')) {
    window.location.href = '/login.html';
  }

  return response;
};

// Global state
let socket = null;
let wsConnected = false;      // Tracks live Socket.IO connection state (for issue #21)
let wsHasConnectedOnce = false;
let lastServerStatus = 'stopped';
let lastServerRunning = false;
let currentServerId = null;
let currentServerCategory = null;  // 'unmodded' | 'modded' | 'bedrock' — drives Bedrock-only UI hiding
let currentPath = '';
let currentEditingFile = '';
let fileEditorRequestId = 0;
let editingServerId = null;
let servers = [];
let currentUser = null;

// ==================== Notifications ====================

function showNotification(message, type = 'info') {
  // Use the toast system
  showToast(message, type);
}

// ==================== Toast Notification System ====================

let _toastCounter = 0;

function showToast(message, type = 'info', duration = 5000) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const icons = { info: 'ℹ️', success: '✅', warning: '⚠️', error: '❌' };
  const id = `toast-${++_toastCounter}`;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.id = id;
  toast.style.position = 'relative';
  toast.innerHTML = `
    <span class="toast-icon">${icons[type] || icons.info}</span>
    <span class="toast-message">${escapeHtml(message)}</span>
    <button class="toast-close" onclick="removeToast('${id}')">&times;</button>
    <div class="toast-progress" style="animation-duration: ${duration}ms;"></div>
  `;

  container.appendChild(toast);

  // Limit to 5 visible toasts
  while (container.children.length > 5) {
    container.removeChild(container.firstChild);
  }

  setTimeout(() => removeToast(id), duration);
  return id;
}

function removeToast(id) {
  const toast = document.getElementById(id);
  if (!toast) return;
  toast.classList.add('removing');
  setTimeout(() => toast.remove(), 300);
}

// ==================== Confirm Modal System ====================

let _confirmResolve = null;

function confirmAction(message, { title = 'Confirm', icon = '⚠️', okText = 'Confirm', okClass = 'btn-danger', cancelText = 'Cancel' } = {}) {
  return new Promise((resolve) => {
    _confirmResolve = resolve;

    document.getElementById('confirm-modal-icon').textContent = icon;
    document.getElementById('confirm-modal-title').textContent = title;
    document.getElementById('confirm-modal-body').textContent = message;

    const okBtn = document.getElementById('confirm-modal-ok');
    okBtn.textContent = okText;
    okBtn.className = `btn ${okClass}`;

    document.getElementById('confirm-modal-cancel').textContent = cancelText;
    document.getElementById('confirm-modal-overlay').classList.add('active');

    // Set up handlers (one-shot)
    okBtn.onclick = () => closeConfirmModal(true);
    document.getElementById('confirm-modal-cancel').onclick = () => closeConfirmModal(false);
    document.getElementById('confirm-modal-overlay').onclick = (e) => {
      if (e.target.id === 'confirm-modal-overlay') closeConfirmModal(false);
    };
  });
}

function closeConfirmModal(result) {
  document.getElementById('confirm-modal-overlay').classList.remove('active');
  if (_confirmResolve) {
    _confirmResolve(result);
    _confirmResolve = null;
  }
}

// ==================== Skeleton Loaders ====================

function showTableSkeleton(tbodyId, cols, rows = 5) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  const widths = ['w-60', 'w-20', 'w-40', 'w-20'];
  tbody.innerHTML = Array.from({ length: rows }, () =>
    `<tr class="skeleton-row">${Array.from({ length: cols }, (_, i) =>
      `<td><div class="skeleton-cell ${widths[i % widths.length]}"></div></td>`
    ).join('')}</tr>`
  ).join('');
}

// ==================== Pagination Utility ====================

const PAGE_SIZE = 50;

function renderPagination(containerId, totalItems, currentPage, onPageChange) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const totalPages = Math.ceil(totalItems / PAGE_SIZE);
  if (totalPages <= 1) {
    container.innerHTML = '';
    return;
  }

  let html = '';
  html += `<button ${currentPage <= 1 ? 'disabled' : ''} onclick="(${onPageChange.name || 'void'})(${currentPage - 1})">‹ Prev</button>`;

  // Show page numbers with ellipsis
  const pages = [];
  pages.push(1);
  for (let p = Math.max(2, currentPage - 1); p <= Math.min(totalPages - 1, currentPage + 1); p++) {
    pages.push(p);
  }
  if (totalPages > 1) pages.push(totalPages);

  // Deduplicate and sort
  const uniquePages = [...new Set(pages)].sort((a, b) => a - b);

  let prev = 0;
  uniquePages.forEach(p => {
    if (p - prev > 1) html += `<span class="pagination-info">…</span>`;
    html += `<button class="${p === currentPage ? 'active' : ''}" onclick="(${onPageChange.name || 'void'})(${p})">${p}</button>`;
    prev = p;
  });

  html += `<button ${currentPage >= totalPages ? 'disabled' : ''} onclick="(${onPageChange.name || 'void'})(${currentPage + 1})">Next ›</button>`;
  html += `<span class="pagination-info">${totalItems} items</span>`;

  container.innerHTML = html;
}

// ==================== Authentication ====================

async function checkAuth() {
  try {
    const response = await fetch('/api/auth/me');
    if (response.ok) {
      currentUser = await response.json();
      window.currentUser = currentUser;
      updateUserUI();
      return true;
    } else {
      // Not authenticated, redirect to login
      window.location.href = '/login.html';
      return false;
    }
  } catch (err) {
    window.location.href = '/login.html';
    return false;
  }
}

function updateUserUI() {
  const userInfo = document.getElementById('user-info');
  if (userInfo && currentUser) {
    const displayName = currentUser.displayName || currentUser.name || currentUser.username;
    const groupName = currentUser.groupName || 'No Group';
    userInfo.innerHTML = `
      <div class="user-display">
        <span class="user-name">${escapeHtml(displayName)}</span>
        <span class="group-badge">${escapeHtml(groupName)}</span>
      </div>
      <div class="user-actions">
        <button class="btn-icon" onclick="openProfileSettings()" title="Profile Settings">⚙️</button>
        <button class="btn-icon" onclick="logout()" title="Logout">🚪</button>
      </div>
    `;
  }

  const settingsLink = document.getElementById('settings-link');
  if (settingsLink && currentUser) {
    const hasPanel = currentUser.permissions && currentUser.permissions.some(p => p === '*' || p.startsWith('panel.'));
    settingsLink.style.display = hasPanel ? 'inline-block' : 'none';
  }

  // Server creation is gated on servers.create server-side (POST /api/servers and
  // /api/servers/import) — hide the entry points rather than let them 403.
  if (currentUser) {
    const canCreate = currentUser.permissions && currentUser.permissions.some(p => p === '*' || p === 'servers.create');
    ['add-server-btn', 'welcome-add-btn'].forEach(id => {
      const btn = document.getElementById(id);
      if (btn) btn.style.display = canCreate ? '' : 'none';
    });
  }
}

async function loadBranding() {
  try {
    const response = await fetch('/api/settings/branding');
    if (response.ok) {
      const branding = await response.json();
      
      // Update page title
      if (branding.siteTitle) {
        document.title = branding.siteTitle;
        const siteTitle = document.getElementById('site-title');
        if (siteTitle) {
          siteTitle.textContent = '🎮 ' + branding.siteTitle;
        }
      }
      
      // Update favicon if provided
      if (branding.siteIcon) {
        let favicon = document.querySelector('link[rel="icon"]');
        if (!favicon) {
          favicon = document.createElement('link');
          favicon.rel = 'icon';
          document.head.appendChild(favicon);
        }
        // siteIcon is now a filename stored on the server
        favicon.href = `/public/favicons/${branding.siteIcon}`;
      }
      
      // Update footer
      const footer = document.getElementById('app-footer');
      if (footer) {
        let footerContent = '';
        if (branding.footerAddition) {
          footerContent = branding.footerAddition + ' | ';
        }
        footerContent += 'Made By TwiStarSystems © All Rights Reserved';
        footer.innerHTML = footerContent;
      }
    }
  } catch (err) {
    console.log('Failed to load branding:', err);
  }
}

async function logout() {
  if (!await confirmAction('Are you sure you want to logout?', { title: 'Logout', icon: '🚪', okText: 'Logout', okClass: 'btn-primary' })) return;
  
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
  } catch (err) {
    // Ignore errors
  }
  window.location.href = '/login.html';
}

// ==================== Profile Settings ====================

function openProfileSettings() {
  try {
    // Populate profile display section (read-only)
    document.getElementById('profile-display-username').textContent = currentUser.username;
    const roleDisplay = document.getElementById('profile-display-role');
    roleDisplay.textContent = (currentUser.groupName || 'No Group').toUpperCase();
    roleDisplay.className = 'profile-info-value profile-role-badge group-badge';
    
    // Populate editable fields
    document.getElementById('profile-username').value = currentUser.username;
    document.getElementById('profile-name').value = currentUser.name || '';
    document.getElementById('profile-email').value = currentUser.email || '';
    
    // Clear password fields
    document.getElementById('profile-old-password').value = '';
    document.getElementById('profile-new-password').value = '';
    document.getElementById('profile-confirm-password').value = '';
    
    // Update MFA status
    updateMFAStatus();
    
    // Show modal
    document.getElementById('profile-modal').style.display = 'flex';
  } catch (err) {
    console.error('Error opening profile settings:', err);
    // Still show the modal even if there's an error
    document.getElementById('profile-modal').style.display = 'flex';
  }
}

function closeProfileModal() {
  document.getElementById('profile-modal').style.display = 'none';
}

async function saveProfileSettings() {
  const username = document.getElementById('profile-username').value.trim();
  const name = document.getElementById('profile-name').value.trim();
  const email = document.getElementById('profile-email').value.trim();
  
  if (!username) {
    showNotification('Username is required', 'error');
    return;
  }
  
  try {
    // Update username if changed
    if (username !== currentUser.username) {
      const usernameResponse = await fetch('/api/auth/profile/username', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
      });
      
      const usernameData = await usernameResponse.json();
      
      if (!usernameResponse.ok) {
        showNotification(usernameData.error || 'Failed to update username', 'error');
        return;
      }
      
      currentUser.username = username;
    }
    
    // Update name if changed
    if (name !== (currentUser.name || '')) {
      const nameResponse = await fetch('/api/auth/profile/name', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name })
      });
      
      const nameData = await nameResponse.json();
      
      if (!nameResponse.ok) {
        showNotification(nameData.error || 'Failed to update name', 'error');
        return;
      }
      
      currentUser.name = name;
    }
    
    // Update email if changed
    if (email !== (currentUser.email || '')) {
      const emailResponse = await fetch('/api/auth/profile/email', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      
      const emailData = await emailResponse.json();
      
      if (!emailResponse.ok) {
        showNotification(emailData.error || 'Failed to update email', 'error');
        return;
      }
      
      currentUser.email = email;
    }
    
    showNotification('Profile updated successfully', 'success');
    updateUserUI();
    closeProfileModal();
  } catch (err) {
    showNotification('Failed to update profile: ' + err.message, 'error');
  }
}

async function changePassword() {
  const oldPassword = document.getElementById('profile-old-password').value;
  const newPassword = document.getElementById('profile-new-password').value;
  const confirmPassword = document.getElementById('profile-confirm-password').value;
  
  // Validation
  if (!oldPassword || !newPassword || !confirmPassword) {
    showNotification('All password fields are required', 'error');
    return;
  }
  
  if (newPassword !== confirmPassword) {
    showNotification('New passwords do not match', 'error');
    return;
  }
  
  if (newPassword.length < 6) {
    showNotification('New password must be at least 6 characters', 'error');
    return;
  }
  
  try {
    const response = await fetch('/api/auth/password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        oldPassword,
        newPassword
      })
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      showNotification(data.error || 'Failed to change password', 'error');
      return;
    }
    
    showNotification('Password changed successfully', 'success');
    
    // Clear password fields
    document.getElementById('profile-old-password').value = '';
    document.getElementById('profile-new-password').value = '';
    document.getElementById('profile-confirm-password').value = '';
  } catch (err) {
    showNotification('Failed to change password: ' + err.message, 'error');
  }
}

// ==================== MFA Functions ====================

let currentMFASecret = null;
let currentRecoveryCode = null;

function updateMFAStatus() {
  if (!currentUser) {
    console.warn('currentUser not defined yet');
    return;
  }
  
  const mfaEnabled = currentUser.mfaEnabled === true;
  
  const mfaDisabledView = document.getElementById('mfa-disabled-view');
  const mfaEnabledView = document.getElementById('mfa-enabled-view');
  const mfaSetupSection = document.getElementById('mfa-setup-section');
  const mfaRecoverySection = document.getElementById('mfa-recovery-section');
  
  if (mfaDisabledView) mfaDisabledView.style.display = mfaEnabled ? 'none' : 'block';
  if (mfaEnabledView) mfaEnabledView.style.display = mfaEnabled ? 'block' : 'none';
  if (mfaSetupSection) mfaSetupSection.style.display = 'none';
  if (mfaRecoverySection) mfaRecoverySection.style.display = 'none';
}

async function setupMFA() {
  try {
    const response = await fetch('/api/auth/mfa/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      showNotification(data.error || 'Failed to setup MFA', 'error');
      return;
    }
    
    currentMFASecret = data.secret;
    
    // Display QR code
    document.getElementById('mfa-qr-code').src = data.qrCode;
    document.getElementById('mfa-secret-text').value = data.manualEntry;
    
    // Show setup section
    document.getElementById('mfa-status-section').style.display = 'none';
    document.getElementById('mfa-setup-section').style.display = 'block';
    document.getElementById('mfa-verify-code').value = '';
  } catch (err) {
    showNotification('Failed to setup MFA: ' + err.message, 'error');
  }
}

function copyMFASecret() {
  const secretInput = document.getElementById('mfa-secret-text');
  secretInput.select();
  document.execCommand('copy');
  showNotification('Secret copied to clipboard', 'success');
}

async function verifyMFACode() {
  const code = document.getElementById('mfa-verify-code').value.trim();
  
  if (!code || code.length !== 6) {
    showNotification('Please enter a 6-digit code', 'error');
    return;
  }
  
  try {
    const response = await fetch('/api/auth/mfa/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret: currentMFASecret,
        code: code
      })
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      showNotification(data.error || 'Invalid verification code', 'error');
      return;
    }
    
    currentRecoveryCode = data.recoveryCode;
    
    // Show recovery code
    document.getElementById('mfa-recovery-code').textContent = currentRecoveryCode;
    document.getElementById('mfa-setup-section').style.display = 'none';
    document.getElementById('mfa-recovery-section').style.display = 'block';
    
    // Enable complete button when checkbox is checked
    document.getElementById('mfa-recovery-confirm').addEventListener('change', (e) => {
      document.getElementById('mfa-complete-btn').disabled = !e.target.checked;
    });
  } catch (err) {
    showNotification('Failed to verify code: ' + err.message, 'error');
  }
}

function copyRecoveryCode() {
  const code = document.getElementById('mfa-recovery-code').textContent;
  navigator.clipboard.writeText(code).then(() => {
    showNotification('Recovery code copied to clipboard', 'success');
  }).catch(() => {
    // Fallback for older browsers
    const textarea = document.createElement('textarea');
    textarea.value = code;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    showNotification('Recovery code copied to clipboard', 'success');
  });
}

function completeMFASetup() {
  showNotification('MFA has been enabled successfully!', 'success');
  currentUser.mfaEnabled = true;
  
  // Reset view
  document.getElementById('mfa-recovery-section').style.display = 'none';
  document.getElementById('mfa-status-section').style.display = 'block';
  document.getElementById('mfa-recovery-confirm').checked = false;
  updateMFAStatus();
  
  currentMFASecret = null;
  currentRecoveryCode = null;
}

function cancelMFASetup() {
  document.getElementById('mfa-setup-section').style.display = 'none';
  document.getElementById('mfa-status-section').style.display = 'block';
  currentMFASecret = null;
}

async function disableMFA() {
  const password = prompt('Enter your password to disable MFA:');
  
  if (!password) return;
  
  try {
    const response = await fetch('/api/auth/mfa/disable', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      showNotification(data.error || 'Failed to disable MFA', 'error');
      return;
    }
    
    showNotification('MFA has been disabled', 'success');
    currentUser.mfaEnabled = false;
    updateMFAStatus();
  } catch (err) {
    showNotification('Failed to disable MFA: ' + err.message, 'error');
  }
}


// ==================== Socket.IO Connection ====================

function connectWebSocket() {
  socket = io({
    transports: ['websocket', 'polling'], // Try WebSocket first, fall back to polling
    reconnection: true,
    reconnectionDelay: 1000,          // Wait 1s before first reconnect attempt
    reconnectionDelayMax: 5000,       // Cap reconnect delay at 5s
    reconnectionAttempts: Infinity,
    timeout: 15000,                   // 15s connection timeout
    upgrade: true                     // Allow upgrading from polling to WebSocket
  });
  
  socket.on('connect', () => {
    console.log('Socket.IO connected');
    wsConnected = true;
    wsHasConnectedOnce = true;
    setWsBanner(null);
    // Re-enable command input now that we're back online (server-running state permitting).
    updateServerStatus(lastServerStatus, lastServerRunning);
    // Re-subscribe to current server on reconnect (don't clear terminal)
    if (currentServerId) {
      socket.emit('subscribe', { serverId: currentServerId });
    }
    // Resync the task list in case job events were missed while disconnected.
    loadJobs();
  });
  
  socket.on('message', (data) => {
    // Only process messages for the currently selected server
    if (data.serverId === currentServerId) {
      if (data.type === 'output' || data.type === 'error' || data.type === 'info') {
        appendTerminalOutput(data.data);
      }
      if (data.type === 'status') {
        const status = data.status || (data.running ? 'running' : 'stopped');
        updateServerStatus(status, data.running);
      }
    }
    // Update server list status
    if (data.type === 'status') {
      const status = data.status || (data.running ? 'running' : 'stopped');
      updateServerInList(data.serverId, data.running, status);
    }
    // Track online players from join/leave events
    if (data.type === 'player_join' || data.type === 'player_leave') {
      const tab = document.getElementById('players-tab');
      if (tab && tab.classList.contains('active') && data.serverId === currentServerId) {
        loadOnlinePlayers();
      }
    }
  });
  
  socket.on('disconnect', (reason) => {
    console.log('Socket.IO disconnected:', reason);
    wsConnected = false;
    setWsBanner('⚠ Disconnected from server — attempting to reconnect…');
    // Force command input off while disconnected, regardless of last-known server state.
    updateServerStatus(lastServerStatus, lastServerRunning);
  });

  socket.on('connect_error', (error) => {
    console.error('Socket.IO error:', error);
    // Covers the case where the very first connection attempt fails (server
    // unreachable on page load) — 'disconnect' never fires for that case.
    if (!wsHasConnectedOnce) {
      setWsBanner('⚠ Unable to reach server — retrying…');
    }
  });

  // Manager-level reconnection events (Socket.IO v4 emits these on socket.io, not socket).
  socket.io.on('reconnect_attempt', (attempt) => {
    setWsBanner(`⚠ Disconnected from server — reconnecting… (attempt ${attempt})`);
  });
  
  // Listen for scheduled backup events
  socket.on('backup_completed', (data) => {
    if (data.scheduled) {
      showNotification(`📅 Scheduled backup completed for server: ${data.backup}`, 'success');
      // Refresh backup list if we're on that server
      if (data.serverId === currentServerId) {
        loadBackups();
      }
    }
  });
  
  socket.on('backup_failed', (data) => {
    if (data.scheduled) {
      showNotification(`❌ Scheduled backup failed: ${data.error}`, 'error');
    }
  });

  // Unified background-job events (backups, restores, deletes, JAR swaps, zips).
  ['job_queued', 'job_started', 'job_progress'].forEach(evt => {
    socket.on(evt, (data) => { if (data && data.job) upsertJob(data.job); });
  });
  socket.on('job_completed', (data) => { if (data && data.job) onJobFinished(data.job); });
  socket.on('job_failed', (data) => { if (data && data.job) onJobFinished(data.job); });
  socket.on('job_cancelled', (data) => { if (data && data.job) onJobFinished(data.job); });
}

// ==================== Background Tasks Panel ====================

// In-memory mirror of the jobs the server knows about, keyed by id.
let jobsCache = {};

const JOB_ACTIVE = ['queued', 'running'];

async function loadJobs() {
  try {
    const data = await apiRequest('/api/jobs');
    jobsCache = {};
    (data.jobs || []).forEach(j => { jobsCache[j.id] = j; });
    renderJobs();
    updateJobsBadge();
  } catch (error) {
    console.error('Failed to load jobs:', error);
  }
}

function upsertJob(job) {
  jobsCache[job.id] = job;
  renderJobs();
  updateJobsBadge();
}

// Called for job_completed / job_failed / job_cancelled — update the cache,
// surface a notification, and refresh any affected views.
function onJobFinished(job) {
  upsertJob(job);

  const name = job.title || 'Task';
  if (job.status === 'completed') {
    showNotification(`✅ ${name} — done`, 'success');
  } else if (job.status === 'failed') {
    showNotification(`❌ ${name} failed: ${job.error || 'unknown error'}`, 'error');
  } else if (job.status === 'cancelled') {
    showNotification(`⚪ ${name} cancelled`, 'info');
  }

  // Refresh affected views.
  if ((job.type === 'backup' || job.type === 'restore') &&
      job.status === 'completed' && job.serverId === currentServerId) {
    if (typeof loadBackups === 'function') loadBackups();
  }
  if (job.type === 'delete_server' && job.status === 'completed') {
    loadServers();
  }
}

function updateJobsBadge() {
  const badge = document.getElementById('tasks-badge');
  if (!badge) return;
  const active = Object.values(jobsCache).filter(j => JOB_ACTIVE.includes(j.status)).length;
  if (active > 0) {
    badge.textContent = active;
    badge.style.display = '';
  } else {
    badge.style.display = 'none';
  }
}

function renderJobs() {
  const list = document.getElementById('jobs-list');
  if (!list) return;

  const jobs = Object.values(jobsCache)
    .sort((a, b) => (b.created || '').localeCompare(a.created || ''));

  if (jobs.length === 0) {
    list.innerHTML = '<div class="jobs-empty">No tasks yet.</div>';
    return;
  }

  list.innerHTML = jobs.map(job => {
    const active = JOB_ACTIVE.includes(job.status);
    const pct = Math.max(0, Math.min(100, job.progress || 0));
    const canDownload = job.type === 'zip_download' && job.status === 'completed';

    let actions = '';
    if (active) {
      actions += `<button class="btn btn-small btn-danger" onclick="cancelJob('${job.id}')">Cancel</button>`;
    } else {
      if (canDownload) {
        actions += `<button class="btn btn-small btn-success" onclick="downloadJobArtifact('${job.id}')">⬇ Download</button>`;
      }
      actions += `<button class="btn btn-small" onclick="dismissJob('${job.id}')">Dismiss</button>`;
    }

    const detail = job.status === 'failed'
      ? `<div class="job-error">${escapeHtml(job.error || 'Failed')}</div>`
      : (job.message ? `<div class="job-message">${escapeHtml(job.message)}</div>` : '');

    return `
      <div class="job-item" data-job-id="${job.id}">
        <div class="job-item-top">
          <span class="job-title">${escapeHtml(job.title || job.type)}</span>
          <span class="job-status-chip ${job.status}">${escapeHtml(job.status)}</span>
        </div>
        ${detail}
        ${active ? `<div class="job-progress"><div class="job-progress-fill" style="width:${pct}%"></div></div>` : ''}
        <div class="job-actions">${actions}</div>
      </div>
    `;
  }).join('');
}

function openJobsPanel() {
  const panel = document.getElementById('jobs-panel');
  const overlay = document.getElementById('jobs-overlay');
  if (!panel) return;
  panel.classList.add('open');
  panel.setAttribute('aria-hidden', 'false');
  if (overlay) overlay.classList.add('open');
  loadJobs();
}

function closeJobsPanel() {
  const panel = document.getElementById('jobs-panel');
  const overlay = document.getElementById('jobs-overlay');
  if (panel) {
    panel.classList.remove('open');
    panel.setAttribute('aria-hidden', 'true');
  }
  if (overlay) overlay.classList.remove('open');
}

function toggleJobsPanel() {
  const panel = document.getElementById('jobs-panel');
  if (panel && panel.classList.contains('open')) {
    closeJobsPanel();
  } else {
    openJobsPanel();
  }
}

async function cancelJob(jobId) {
  try {
    await apiRequest(`/api/jobs/${jobId}/cancel`, { method: 'POST' });
  } catch (error) {
    showNotification('Failed to cancel task: ' + error.message, 'error');
  }
}

async function dismissJob(jobId) {
  try {
    await apiRequest(`/api/jobs/${jobId}`, { method: 'DELETE' });
    delete jobsCache[jobId];
    renderJobs();
    updateJobsBadge();
  } catch (error) {
    showNotification('Failed to dismiss task: ' + error.message, 'error');
  }
}

function downloadJobArtifact(jobId) {
  window.location.href = `/api/jobs/${jobId}/download`;
}

// ==================== API Functions ====================

// Note: apiRequest is in utils.js for shared use across all pages

// ==================== Server List Management ====================

async function loadServers() {
  try {
    const data = await apiRequest('/api/servers');
    servers = data.servers || [];
    renderServerList();
  } catch (error) {
    console.error('Failed to load servers:', error);
  }
}

function renderServerList() {
  const container = document.getElementById('server-list');
  const actionsBar = document.getElementById('server-list-actions');
  const searchInput = document.getElementById('server-search');
  const filter = (searchInput ? searchInput.value : '').toLowerCase().trim();
  
  const filtered = filter
    ? servers.filter(s => s.name.toLowerCase().includes(filter) ||
        (s.status || '').toLowerCase().includes(filter) ||
        (s.port && String(s.port).includes(filter)))
    : servers;

  if (servers.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <p>No servers configured</p>
        <small>Click "Add" to create one</small>
      </div>
    `;
    if (actionsBar) actionsBar.style.display = 'none';
    return;
  }
  
  if (actionsBar) actionsBar.style.display = 'flex';
  
  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <p>No matching servers</p>
        <small>Try a different search term</small>
      </div>
    `;
    return;
  }

  container.innerHTML = filtered.map(server => {
    const status = server.status || 'stopped';
    const statusClasses = {
      'stopped': 'status-stopped',
      'starting': 'status-starting',
      'running': 'status-running',
      'stopping': 'status-stopping',
      'unresponsive': 'status-unresponsive'
    };
    
    const statusTexts = {
      'stopped': 'Stopped',
      'starting': 'Starting...',
      'running': server.port ? `Running - ${server.port}` : 'Running',
      'stopping': 'Stopping...',
      'unresponsive': 'Unresponsive'
    };
    
    return `
      <div class="server-item ${server.id === currentServerId ? 'active' : ''}" 
           data-server-id="${server.id}" 
           onclick="selectServer('${server.id}')">
        <div class="server-item-status ${statusClasses[status] || 'status-stopped'}">●</div>
        <div class="server-item-info">
          <div class="server-item-name">${escapeHtml(server.name)}</div>
          <div class="server-item-state">${statusTexts[status] || 'Unknown'}</div>
        </div>
      </div>
    `;
  }).join('');
}

function updateServerInList(serverId, isRunning, status) {
  const server = servers.find(s => s.id === serverId);
  if (server) {
    server.running = isRunning;
    server.status = status || (isRunning ? 'running' : 'stopped');
    renderServerList();
  }
}

// ==================== Server Selection ====================

async function selectServer(serverId) {
  currentServerId = serverId;
  currentServerCategory = null;  // set from the server details fetch below
  currentPath = '';
  backupHistoryLoaded = false;  // Reset history state on server change
  
  // Update UI
  document.getElementById('no-server-view').style.display = 'none';
  document.getElementById('server-view').style.display = 'flex';
  
  // Update server list selection
  renderServerList();
  
  // Clear terminal
  clearTerminal();
  
  // Subscribe to server output
  if (socket && socket.connected) {
    socket.emit('subscribe', { serverId: currentServerId });
  }
  
  // Load server details
  await loadServerDetails();
  
  // Switch to terminal tab
  switchTab('terminal');
}

async function loadServerDetails() {
  if (!currentServerId) return;
  
  try {
    const server = await apiRequest(`/api/servers/${currentServerId}`);
    currentServerCategory = server.category || null;

    // Update header — show Name - Engine - Version
    const _typeLabel = (server.serverType || '').toUpperCase();
    const _verLabel = (server.version && server.version.toLowerCase() !== 'unknown') ? server.version : '';
    const _nameParts = [server.name];
    if (_typeLabel && _typeLabel !== 'UNMODDED' && _typeLabel !== 'IMPORTED') _nameParts.push(_typeLabel);
    if (_verLabel) _nameParts.push(_verLabel);
    document.getElementById('server-name').textContent = _nameParts.join(' - ');
    const status = server.status || (server.running ? 'running' : 'stopped');
    updateServerStatus(status, server.running);
    
    // Show/hide Mods tab based on server category
    const modsTabBtn = document.getElementById('mods-tab-btn');
    if (server.category === 'modded') {
      modsTabBtn.style.display = '';
    } else {
      modsTabBtn.style.display = 'none';
      // If currently on mods tab, switch to terminal
      if (document.querySelector('.tab-button.active[data-tab="mods"]')) {
        switchTab('terminal');
      }
    }
    
    // Hide Resource Pack tab for Bedrock servers
    const resourcepackTabBtn = document.getElementById('resourcepack-tab-btn');
    if (server.category === 'bedrock') {
      resourcepackTabBtn.style.display = 'none';
      // If currently on resourcepack tab, switch to terminal
      if (document.querySelector('.tab-button.active[data-tab="resourcepack"]')) {
        switchTab('terminal');
      }
    } else {
      resourcepackTabBtn.style.display = '';
    }

    // Hide the Java-only Players sections for Bedrock servers
    applyPlayersTabForCategory();

    // Check if server.properties exists and show/hide Properties tab
    const propertiesTabBtn = document.getElementById('properties-tab-btn');
    try {
      const propsCheck = await apiRequest(`/api/servers/${currentServerId}/properties/exists`);
      if (propsCheck.exists) {
        propertiesTabBtn.style.display = '';
      } else {
        propertiesTabBtn.style.display = 'none';
        if (document.querySelector('.tab-button.active[data-tab="properties"]')) {
          switchTab('terminal');
        }
      }
    } catch (err) {
      propertiesTabBtn.style.display = 'none';
    }
  } catch (error) {
    console.error('Failed to load server details:', error);
  }
}

// Shows/hides the disconnected-websocket banner above the terminal (issue #21).
// Pass null/empty to hide it.
function setWsBanner(message) {
  const banner = document.getElementById('ws-status-banner');
  if (!banner) return;
  if (message) {
    banner.textContent = message;
    banner.style.display = '';
  } else {
    banner.style.display = 'none';
  }
}

function updateServerStatus(status, isRunning) {
  status = status || 'stopped';
  lastServerStatus = status;
  lastServerRunning = isRunning;

  const indicator = document.getElementById('status-indicator');
  const text = document.getElementById('status-text');
  const startBtn = document.getElementById('start-btn');
  const restartBtn = document.getElementById('restart-btn');
  const stopBtn = document.getElementById('stop-btn');
  const killBtn = document.getElementById('kill-btn');
  const terminalInput = document.getElementById('terminal-input');
  const sendBtn = document.getElementById('send-btn');

  // Update status indicator and text
  const statusClasses = {
    'stopped': 'status-stopped',
    'starting': 'status-starting',
    'running': 'status-running',
    'stopping': 'status-stopping',
    'unresponsive': 'status-unresponsive'
  };
  
  const statusTexts = {
    'stopped': 'Stopped',
    'starting': 'Starting...',
    'running': 'Running',
    'stopping': 'Stopping...',
    'unresponsive': 'Unresponsive'
  };
  
  indicator.className = statusClasses[status] || 'status-stopped';
  text.textContent = statusTexts[status] || 'Unknown';
  
  // Button states based on status
  const canStart = status === 'stopped';
  const canRestart = status === 'running';
  const canStop = status === 'running' || status === 'unresponsive';
  const canKill = status === 'starting' || status === 'running' || status === 'stopping' || status === 'unresponsive';
  // Command input additionally requires a live websocket, since commands are sent via socket.emit (issue #21).
  const canCommand = status === 'running' && wsConnected;

  startBtn.disabled = !canStart;
  restartBtn.disabled = !canRestart;
  stopBtn.disabled = !canStop;
  killBtn.disabled = !canKill;
  terminalInput.disabled = !canCommand;
  sendBtn.disabled = !canCommand;

  // Gray out quick command buttons when server is not running
  const quickcmdsGrid = document.getElementById('quickcmds-grid');
  if (quickcmdsGrid) {
    quickcmdsGrid.dataset.serverRunning = canCommand ? 'true' : 'false';
    quickcmdsGrid.querySelectorAll('.quickcmd-btn').forEach(btn => {
      btn.disabled = !canCommand;
    });
  }
  updateServerInList(currentServerId, isRunning, status);
}

// ==================== Server Actions ====================

async function startServer() {
  if (!currentServerId) return;
  
  try {
    // First check if server is managed (has managed.conf) and validate fields
    const managedCheck = await apiRequest(`/api/servers/${currentServerId}/managed`);
    
    if (!managedCheck.managed) {
      // Show management modal
      showManagementModal();
      return;
    }
    
    // Check if managed.conf has all required fields
    if (!managedCheck.valid && managedCheck.missingFields && managedCheck.missingFields.length > 0) {
      showMissingFieldsModal(managedCheck.missingFields, managedCheck.data);
      return;
    }
    
    // Check if EULA has been accepted
    const eulaCheck = await apiRequest(`/api/servers/${currentServerId}/eula`);
    
    if (!eulaCheck.accepted) {
      // Show EULA acceptance modal
      showEulaModal();
      return;
    }
    
    // All checks passed, start the server
    // Clear terminal before starting
    clearTerminal();
    
    const result = await apiRequest(`/api/servers/${currentServerId}/start`, { method: 'POST' });
    if (result.pending) return;
    if (result.success) {
      appendTerminalOutput('Starting server...\n');
      updateServerStatus('starting', false);
    }
  } catch (error) {
    showNotification('Failed to start server: ' + error.message, 'error');
  }
}

function showMissingFieldsModal(missingFields, currentData) {
  // Remove existing modal if any
  const existing = document.getElementById('missing-fields-modal');
  if (existing) existing.remove();
  
  const server = servers.find(s => s.id === currentServerId);
  
  // Build form fields for missing items
  let fieldsHtml = '';
  
  for (const field of missingFields) {
    let inputHtml = '';
    
    switch(field) {
      case 'Engine':
        inputHtml = `
          <select id="missing-${field}" class="form-control" required>
            <option value="">Select engine...</option>
            <option value="Vanilla">Vanilla</option>
            <option value="Paper">Paper</option>
            <option value="Folia">Folia</option>
            <option value="Purpur">Purpur</option>
            <option value="Spigot">Spigot</option>
            <option value="Forge">Forge</option>
            <option value="NeoForge">NeoForge</option>
            <option value="Fabric">Fabric</option>
          </select>
        `;
        break;
      case 'Modded':
        inputHtml = `
          <select id="missing-${field}" class="form-control" required>
            <option value="">Select...</option>
            <option value="false">No (Vanilla)</option>
            <option value="true">Yes (Modded/Plugins)</option>
          </select>
        `;
        break;
      case 'EULAAccepted':
        inputHtml = `
          <select id="missing-${field}" class="form-control" required>
            <option value="false">Not Accepted</option>
            <option value="true">Accepted</option>
          </select>
        `;
        break;
      case 'Owner':
        inputHtml = `<input type="text" id="missing-${field}" class="form-control" placeholder="Username" value="${currentUser?.username || 'admin'}" required>`;
        break;
      case 'ServerName':
        inputHtml = `<input type="text" id="missing-${field}" class="form-control" placeholder="Server name" value="${escapeHtml(server?.name || '')}" required>`;
        break;
      default:
        inputHtml = `<input type="text" id="missing-${field}" class="form-control" placeholder="Enter value..." required>`;
    }
    
    fieldsHtml += `
      <div class="form-group">
        <label for="missing-${field}">${field}:</label>
        ${inputHtml}
      </div>
    `;
  }
  
  const modal = document.createElement('div');
  modal.id = 'missing-fields-modal';
  modal.className = 'modal active';
  modal.innerHTML = `
    <div class="modal-content modal-medium">
      <div class="modal-header">
        <h2>⚠️ Configuration Incomplete</h2>
        <button class="close-btn" onclick="closeMissingFieldsModal()">&times;</button>
      </div>
      <div class="missing-fields-content">
        <p>The <code>managed.conf</code> file for <strong>"${escapeHtml(server?.name || 'this server')}"</strong> is missing some required fields.</p>
        <p class="missing-fields-info">Please provide the following information:</p>
        <form id="missing-fields-form" onsubmit="submitMissingFields(event)">
          ${fieldsHtml}
          <div class="modal-footer">
            <button type="button" class="btn" onclick="closeMissingFieldsModal()">Cancel</button>
            <button type="submit" class="btn btn-success">Save & Continue</button>
          </div>
        </form>
      </div>
    </div>
  `;
  
  document.body.appendChild(modal);
  
  // Close on background click
  modal.onclick = (e) => {
    if (e.target.id === 'missing-fields-modal') closeMissingFieldsModal();
  };
}

function closeMissingFieldsModal() {
  const modal = document.getElementById('missing-fields-modal');
  if (modal) modal.remove();
}

async function submitMissingFields(e) {
  e.preventDefault();
  
  const form = document.getElementById('missing-fields-form');
  const inputs = form.querySelectorAll('input, select');
  
  const data = {};
  for (const input of inputs) {
    const field = input.id.replace('missing-', '');
    data[field] = input.value;
  }
  
  try {
    await apiRequest(`/api/servers/${currentServerId}/managed/update`, {
      method: 'POST',
      body: JSON.stringify(data)
    });
    
    closeMissingFieldsModal();
    showNotification('Configuration updated successfully', 'success');
    
    // Try starting the server again
    startServer();
  } catch (error) {
    console.error('Failed to update managed.conf:', error);
  }
}

function showManagementModal() {
  // Remove existing modal if any
  const existing = document.getElementById('management-modal');
  if (existing) existing.remove();
  
  const server = servers.find(s => s.id === currentServerId);
  
  const modal = document.createElement('div');
  modal.id = 'management-modal';
  modal.className = 'modal active';
  modal.innerHTML = `
    <div class="modal-content modal-medium">
      <div class="modal-header">
        <h2>📋 Enable Server Management</h2>
        <button class="close-btn" onclick="closeManagementModal()">&times;</button>
      </div>
      <div class="management-content">
        <p>The server <strong>"${escapeHtml(server?.name || 'this server')}"</strong> is not yet fully managed by MServer.</p>
        <div class="management-notice">
          <p>Enabling management will:</p>
          <ul>
            <li>Create a <code>managed.conf</code> file in the server directory</li>
            <li>Allow MServer to track server settings and status</li>
            <li>Enable EULA acceptance and other management features</li>
          </ul>
        </div>
        <p class="management-info">ℹ️ This is required for servers imported before management tracking was added, or after app updates.</p>
      </div>
      <div class="modal-footer">
        <button class="btn" onclick="closeManagementModal()">Cancel</button>
        <button class="btn btn-success" onclick="enableManagementAndContinue()">Enable Management</button>
      </div>
    </div>
  `;
  
  document.body.appendChild(modal);
  
  // Close on background click
  modal.onclick = (e) => {
    if (e.target.id === 'management-modal') closeManagementModal();
  };
}

function closeManagementModal() {
  const modal = document.getElementById('management-modal');
  if (modal) modal.remove();
}

async function enableManagementAndContinue() {
  if (!currentServerId) return;
  
  try {
    // Enable management
    const result = await apiRequest(`/api/servers/${currentServerId}/managed/enable`, { method: 'POST' });
    
    if (result.success) {
      closeManagementModal();
      showNotification('Server management enabled', 'success');
      
      // Continue with the start process (will check EULA next)
      await startServer();
    }
  } catch (error) {
    showNotification('Failed to enable management: ' + error.message, 'error');
  }
}

function showEulaModal() {
  // Remove existing modal if any
  const existing = document.getElementById('eula-modal');
  if (existing) existing.remove();
  
  const modal = document.createElement('div');
  modal.id = 'eula-modal';
  modal.className = 'modal active';
  modal.innerHTML = `
    <div class="modal-content modal-medium">
      <div class="modal-header">
        <h2>⚠️ Minecraft EULA</h2>
        <button class="close-btn" onclick="closeEulaModal()">&times;</button>
      </div>
      <div class="eula-content">
        <p>Before starting this Minecraft server, you must accept the <strong>Minecraft End User License Agreement (EULA)</strong>.</p>
        <div class="eula-notice">
          <p>By clicking "Accept EULA", you agree that:</p>
          <ul>
            <li>You have read and agree to the <a href="https://aka.ms/MinecraftEULA" target="_blank">Minecraft EULA</a></li>
            <li>You understand the terms and conditions set by Mojang/Microsoft</li>
            <li>This will create an <code>eula.txt</code> file with <code>eula=true</code></li>
          </ul>
        </div>
        <p class="eula-warning">⚠️ You must accept the EULA to run a Minecraft server.</p>
      </div>
      <div class="modal-footer">
        <button class="btn" onclick="closeEulaModal()">Cancel</button>
        <button class="btn btn-success" onclick="acceptEulaAndStart()">Accept EULA & Start Server</button>
      </div>
    </div>
  `;
  
  document.body.appendChild(modal);
  
  // Close on background click
  modal.onclick = (e) => {
    if (e.target.id === 'eula-modal') closeEulaModal();
  };
}

function closeEulaModal() {
  const modal = document.getElementById('eula-modal');
  if (modal) modal.remove();
}

async function acceptEulaAndStart() {
  if (!currentServerId) return;
  
  try {
    // Accept EULA
    const acceptResult = await apiRequest(`/api/servers/${currentServerId}/eula/accept`, { method: 'POST' });
    
    if (acceptResult.success) {
      closeEulaModal();
      showNotification('EULA accepted successfully', 'success');
      
      // Now start the server
      const result = await apiRequest(`/api/servers/${currentServerId}/start`, { method: 'POST' });
      if (result.success) {
        appendTerminalOutput('EULA accepted. Starting server...\n');
        updateServerStatus('running', true);
      }
    }
  } catch (error) {
    showNotification('Failed to accept EULA: ' + error.message, 'error');
  }
}

async function stopServer() {
  if (!currentServerId) return;
  
  try {
    const result = await apiRequest(`/api/servers/${currentServerId}/stop`, { method: 'POST' });
    if (result.pending) return;
    if (result.success) {
      appendTerminalOutput('Stopping server gracefully...\n');
      setTimeout(() => loadServerDetails(), 2000);
    }
  } catch (error) {
    showNotification('Failed to stop server: ' + error.message, 'error');
  }
}

async function restartServer() {
  if (!currentServerId) return;

  try {
    const result = await apiRequest(`/api/servers/${currentServerId}/restart`, { method: 'POST' });
    if (result.pending) return;
    if (result.success) {
      appendTerminalOutput('Restarting server...\n');
      updateServerStatus('stopping', true);
    }
  } catch (error) {
    showNotification('Failed to restart server: ' + error.message, 'error');
  }
}

async function startAllServers() {
  const stoppedServers = servers.filter(s => s.status === 'stopped');
  if (stoppedServers.length === 0) {
    showNotification('All servers are already running', 'info');
    return;
  }

  const btn = document.getElementById('start-all-btn');
  if (btn) { btn.disabled = true; btn.textContent = `Starting 1/${stoppedServers.length}...`; }

  let started = 0;
  let failed = 0;

  for (let i = 0; i < stoppedServers.length; i++) {
    const server = stoppedServers[i];
    if (btn) btn.textContent = `Starting ${i + 1}/${stoppedServers.length}...`;
    try {
      const result = await apiRequest(`/api/servers/${server.id}/start`, { method: 'POST' });
      if (result.success) started++;
      else failed++;
    } catch (_) {
      failed++;
    }
    // Stagger each startup by 30 seconds (except after the last one) so JVM
    // initialization does not overlap and spike the host CPU.
    if (i < stoppedServers.length - 1) {
      await sleep(30000);
    }
  }

  if (btn) { btn.disabled = false; btn.textContent = 'Start All'; }

  if (failed === 0) {
    showNotification(`Started ${started} server${started !== 1 ? 's' : ''}`, 'success');
  } else {
    showNotification(`Started ${started}, failed ${failed}`, 'warning');
  }

  await loadServers();
}

async function stopAllServers() {
  const runningServers = servers.filter(s => s.status === 'running' || s.status === 'starting');
  if (runningServers.length === 0) {
    showNotification('No servers are running', 'info');
    return;
  }

  const btn = document.getElementById('stop-all-btn');
  if (btn) { btn.disabled = true; btn.textContent = `Stopping 1/${runningServers.length}...`; }

  let stopped = 0;
  let failed = 0;

  for (let i = 0; i < runningServers.length; i++) {
    const server = runningServers[i];
    if (btn) btn.textContent = `Stopping ${i + 1}/${runningServers.length}...`;
    try {
      const result = await apiRequest(`/api/servers/${server.id}/stop`, { method: 'POST' });
      if (result.success) {
        // Wait for the process to actually exit before stopping the next server.
        // The backend already sends a force-kill after 30 s; we allow up to 40 s
        // before declaring a timeout and moving on.
        const didStop = await waitForServerStopped(server.id, 40000);
        if (didStop) {
          stopped++;
        } else {
          // Backend force-kill should have fired by now – try an explicit kill as
          // a last resort so the next server can cleanly shut down.
          try { await apiRequest(`/api/servers/${server.id}/kill`, { method: 'POST' }); } catch (_) {}
          failed++;
        }
      } else {
        failed++;
      }
    } catch (_) {
      failed++;
    }
    // Brief pause between sequential stop commands
    if (i < runningServers.length - 1) await sleep(500);
  }

  if (btn) { btn.disabled = false; btn.textContent = 'Stop All'; }

  if (failed === 0) {
    showNotification(`Stopped ${stopped} server${stopped !== 1 ? 's' : ''}`, 'success');
  } else {
    showNotification(`Stopped ${stopped}, failed ${failed}`, 'warning');
  }

  setTimeout(loadServers, 2000);
}

async function killServer() {
  if (!currentServerId) return;
  
  if (!await confirmAction('Are you sure you want to forcefully kill the server?\n\nThis will immediately terminate the process without saving. Use only if the server is unresponsive.', { title: 'Force Kill Server', icon: '💀', okText: 'Kill Server' })) {
    return;
  }
  
  try {
    const result = await apiRequest(`/api/servers/${currentServerId}/kill`, { method: 'POST' });
    if (result.success) {
      appendTerminalOutput('Server process killed.\n');
      updateServerStatus('stopped', false);
    }
  } catch (error) {
    showNotification('Failed to kill server: ' + error.message, 'error');
  }
}

// ==================== Server CRUD ====================

let currentCreationType = null;

// Track JAR availability for versions (unified)
let uVersionAvailability = {};

// Metadata for the three creation methods — drives the cards, the banner and
// which parts of the form are relevant.
const CREATION_METHODS = {
  'fresh': {
    icon: '🆕',
    title: 'Create Fresh Server',
    desc: 'Build a brand-new server from a downloaded engine.',
    submit: 'Create Server',
    showProps: true,
    allowBedrock: true
  },
  'import': {
    icon: '📦',
    title: 'Import Existing Server',
    desc: 'Upload a ZIP of a server you already run — settings come from the archive.',
    submit: 'Import Server',
    showProps: false,
    allowBedrock: true
  },
  'import-world': {
    icon: '🌍',
    title: 'Import Existing World',
    desc: 'Create a fresh Java server and load your existing world into it.',
    submit: 'Create Server & Import World',
    showProps: true,
    allowBedrock: false
  }
};

async function openAddServerModal() {
  try {
    editingServerId = null;
    currentCreationType = null;

    const modalTitle = document.getElementById('modal-title');
    if (modalTitle) modalTitle.textContent = 'Add Server';
    setModalSubtitle('Choose a creation method to get started');

    // Show creation type selection, hide all forms
    const creationTypeSection = document.getElementById('creation-type-section');
    const unifiedForm = document.getElementById('unified-server-form');
    const manualForm = document.getElementById('manual-server-form');

    if (creationTypeSection) creationTypeSection.style.display = 'block';
    if (unifiedForm) unifiedForm.style.display = 'none';
    if (manualForm) manualForm.style.display = 'none';

    const wizardSteps = document.getElementById('wizard-steps');
    if (wizardSteps) wizardSteps.style.display = 'flex';
    setWizardStep(1);
    clearCreationTypeSelection();

    // Hide version management section (only for editing)
    const versionSection = document.getElementById('version-management-section');
    if (versionSection) versionSection.style.display = 'none';

    // Reset unified form
    resetUnifiedForm();

    // Load server engines (non-blocking)
    loadUnifiedEngines().catch(err => console.error('Failed to load engines:', err));

    // Show modal
    const serverModal = document.getElementById('server-modal');
    if (serverModal) {
      serverModal.classList.add('active');
    }

  } catch (error) {
    console.error('Error in openAddServerModal:', error);
    const serverModal = document.getElementById('server-modal');
    if (serverModal) serverModal.classList.add('active');
  }
}

// ==================== Wizard chrome ====================

function setModalSubtitle(text) {
  const subtitle = document.getElementById('modal-subtitle');
  if (!subtitle) return;
  subtitle.textContent = text || '';
  subtitle.style.display = text ? '' : 'none';
}

function setWizardStep(step) {
  const container = document.getElementById('wizard-steps');
  if (!container) return;
  container.querySelectorAll('.wizard-step').forEach(el => {
    const num = parseInt(el.dataset.step, 10);
    const dot = el.querySelector('.wizard-step-dot');
    el.classList.toggle('is-active', num === step);
    el.classList.toggle('is-done', num < step);
    if (dot) dot.textContent = num < step ? '✓' : String(num);
  });
}

function clearCreationTypeSelection() {
  document.querySelectorAll('.creation-type-btn').forEach(btn => {
    btn.classList.remove('selected');
    btn.setAttribute('aria-checked', 'false');
  });
}

// ==================== Form reset ====================

const U_PROP_DEFAULTS = {
  'u-server-port': '25565',
  'u-max-players': '20',
  'u-gamemode': 'survival',
  'u-difficulty': 'easy',
  'u-level-type': 'minecraft:normal',
  'u-level-seed': '',
  'u-generator-settings': '',
  'u-level-name': 'Bedrock level',
  'u-idle-timeout': '30',
  'u-view-distance': '32',
  'u-tick-distance': '4'
};

const U_TOGGLE_DEFAULTS = {
  'u-pvp': true,
  'u-force-gamemode': false,
  'u-hardcore': false,
  'u-generate-structures': true,
  'u-spawn-npcs': true,
  'u-spawn-animals': true,
  'u-spawn-monsters': true,
  'u-enable-command-block': false,
  'u-allow-list': false
};

function resetUnifiedForm() {
  const setValue = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.value = value;
  };

  setValue('u-name', '');
  setValue('u-category', '');
  setValue('u-engine', '');
  setValue('u-jvm-args', '');
  setValue('u-min-ram', '1G');
  setValue('u-max-ram', '2G');

  const versionSelect = document.getElementById('u-version');
  if (versionSelect) {
    versionSelect.value = '';
    versionSelect.disabled = true;
    versionSelect.innerHTML = '<option value="">Select category first...</option>';
  }

  const uploadJarCheckbox = document.getElementById('u-upload-jar');
  if (uploadJarCheckbox) uploadJarCheckbox.checked = false;
  hideEl('u-custom-jar-upload');

  // Server properties + toggles back to their defaults
  Object.entries(U_PROP_DEFAULTS).forEach(([id, value]) => setValue(id, value));
  Object.entries(U_TOGGLE_DEFAULTS).forEach(([id, checked]) => {
    const el = document.getElementById(id);
    if (el) el.checked = checked;
  });

  // Descriptions back to their neutral copy
  const categoryDesc = document.getElementById('u-category-desc');
  if (categoryDesc) categoryDesc.textContent = 'Choose whether you want a Java or Bedrock server';
  const engineDesc = document.getElementById('u-engine-desc');
  if (engineDesc) engineDesc.textContent = 'Select a server type';
  const versionDesc = document.getElementById('u-version-desc');
  if (versionDesc) versionDesc.textContent = 'Select the Minecraft version';

  // Hide conditional sections
  ['u-engine-group', 'u-version-group', 'u-ram-group', 'u-upload-jar-group',
   'u-import-fields', 'u-world-file-group', 'u-download-status-group'].forEach(hideEl);

  applyPropsEdition('unmodded');
  onUnifiedLevelTypeChange();

  // Reset download status UI
  const versionStatus = document.getElementById('u-version-status');
  const progressFill = document.querySelector('#u-jar-download-status .progress-fill');
  const progressText = document.querySelector('#u-jar-download-status .progress-text');
  const downloadProgress = document.querySelector('#u-jar-download-status .download-progress');
  const downloadInfo = document.querySelector('#u-jar-download-status .download-info');

  if (versionStatus) {
    versionStatus.textContent = '';
    versionStatus.className = 'version-status';
  }
  if (progressFill) progressFill.style.width = '0%';
  if (progressText) progressText.textContent = '0%';
  if (downloadProgress) downloadProgress.style.display = 'none';
  if (downloadInfo) {
    downloadInfo.innerHTML = '';
    downloadInfo.classList.remove('error');
  }
  hideEl('u-bedrock-setup-status');
  uVersionAvailability = {};

  // Reset file inputs
  ['u-import-file', 'u-import-executable', 'u-world-file', 'u-jar-file'].forEach(id => setValue(id, ''));

  // Clear validation state
  uTouchedFields.clear();
  clearAllUnifiedErrors();

  const submitBtn = document.getElementById('u-submit-btn');
  if (submitBtn) {
    submitBtn.textContent = 'Create Server';
    submitBtn.disabled = true;
  }
}

function hideEl(id) {
  const el = document.getElementById(id);
  if (el) el.style.display = 'none';
}

function showEl(id, display = 'flex') {
  const el = document.getElementById(id);
  if (el) el.style.display = display;
}

// The progress/status block sits at the bottom of the configuration column,
// which scrolls — bring it into view the first time it appears.
function showUnifiedStatusGroup() {
  const el = document.getElementById('u-download-status-group');
  if (!el) return;
  const wasHidden = !el.style.display || el.style.display === 'none';
  el.style.display = 'block';
  if (wasHidden) {
    // It is the last thing in the column, so pinning the panel to the bottom
    // shows the whole progress/error block rather than just its first line.
    const body = el.closest('.form-panel-body');
    if (body) body.scrollTop = body.scrollHeight;
  }
}

// ==================== Creation type selection ====================

function selectCreationType(type) {
  const method = CREATION_METHODS[type];
  if (!method) return;

  currentCreationType = type;

  // Visual confirmation on the picked card before the form slides in
  clearCreationTypeSelection();
  const card = document.querySelector(`.creation-type-btn[data-type="${type}"]`);
  if (card) {
    card.classList.add('selected');
    card.setAttribute('aria-checked', 'true');
  }

  const reveal = () => {
    hideEl('creation-type-section');
    showEl('unified-server-form', 'flex');
    setWizardStep(2);
    setModalSubtitle(method.desc);
    configureUnifiedFormForMethod(type);
    scheduleScrollHintRefresh();
    const nameInput = document.getElementById('u-name');
    if (nameInput && nameInput.offsetParent !== null) nameInput.focus();
  };

  const reducedMotion = window.matchMedia
    && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reducedMotion) reveal();
  else setTimeout(reveal, 190);
}

function configureUnifiedFormForMethod(type) {
  const method = CREATION_METHODS[type];
  const categorySelect = document.getElementById('u-category');
  const submitBtn = document.getElementById('u-submit-btn');

  // Method banner
  const setText = (id, text) => {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  };
  setText('u-method-icon', method.icon);
  setText('u-method-title', method.title);
  setText('u-method-desc', method.desc);
  if (submitBtn) submitBtn.textContent = method.submit;

  // Bedrock is only offered where it makes sense
  const bedrockOption = categorySelect
    ? categorySelect.querySelector('option[value="bedrock"]')
    : null;
  if (bedrockOption) bedrockOption.style.display = method.allowBedrock ? '' : 'none';
  if (!method.allowBedrock && categorySelect && categorySelect.value === 'bedrock') {
    categorySelect.value = '';
  }

  // Method-specific fields
  const isImport = type === 'import';
  const nameHint = document.getElementById('u-name-hint');
  const nameInput = document.getElementById('u-name');
  const nameReq = document.getElementById('u-name-req');
  const categoryReq = document.getElementById('u-category-req');

  if (isImport) {
    if (nameInput) nameInput.placeholder = 'Leave blank to use the name from managed.conf';
    if (nameHint) nameHint.textContent = 'Optional — the archive’s managed.conf name is used when blank';
    if (nameReq) nameReq.style.display = 'none';
    if (categoryReq) categoryReq.style.display = 'none';
    showEl('u-import-fields');
    hideEl('u-world-file-group');
  } else {
    if (nameInput) nameInput.placeholder = 'My Minecraft Server';
    if (nameHint) nameHint.textContent = 'The display name shown in the panel';
    if (nameReq) nameReq.style.display = '';
    if (categoryReq) categoryReq.style.display = '';
    hideEl('u-import-fields');
    if (type === 'import-world') showEl('u-world-file-group');
    else hideEl('u-world-file-group');
  }

  // Category drives engine/version/RAM/properties visibility
  onUnifiedCategoryChange();
}

function backToCreationType() {
  if (editingServerId) {
    // Edit mode has no method step to go back to
    closeServerModal();
    return;
  }

  currentCreationType = null;

  hideEl('unified-server-form');
  hideEl('manual-server-form');

  resetUnifiedForm();
  clearCreationTypeSelection();

  setWizardStep(1);
  setModalSubtitle('Choose a creation method to get started');
  showEl('creation-type-section', 'block');
}

// ==================== Unified Form Dynamic Logic ====================

// Show the property fields that belong to the selected edition and hide the rest.
function applyPropsEdition(category) {
  const isBedrock = category === 'bedrock';
  document.querySelectorAll('#u-server-props .prop-java').forEach(el => {
    el.style.display = isBedrock ? 'none' : '';
  });
  document.querySelectorAll('#u-server-props .prop-bedrock').forEach(el => {
    el.style.display = isBedrock ? '' : 'none';
  });
}

// Panels whose body can still be scrolled get a fade at the bottom edge — the
// only reliable "there is more" cue when the browser uses overlay scrollbars.
function refreshPanelScrollHints() {
  document.querySelectorAll('#server-modal .form-panel').forEach(panel => {
    const body = panel.querySelector('.form-panel-body');
    if (!body) return;
    const more = body.scrollHeight - body.clientHeight - body.scrollTop > 4;
    panel.classList.toggle('has-more', more);
  });
}

function scheduleScrollHintRefresh() {
  requestAnimationFrame(refreshPanelScrollHints);
}

function setPropsPanelVisible(visible) {
  const panel = document.getElementById('u-server-props');
  const columns = document.querySelector('#unified-server-form .unified-form-columns');
  if (panel) panel.style.display = visible ? 'flex' : 'none';
  if (columns) columns.classList.toggle('single', !visible);
}

function onUnifiedLevelTypeChange() {
  const levelType = (document.getElementById('u-level-type') || {}).value || '';
  const usesGenerator = levelType === 'minecraft:flat' || levelType === 'minecraft:single_biome_surface';
  const hint = document.getElementById('u-generator-settings-hint');
  if (hint) {
    hint.textContent = usesGenerator
      ? 'Used by this level type — leave blank for the preset default'
      : 'Only used by the Superflat and Single Biome level types';
  }
}

function onUnifiedCategoryChange() {
  const category = (document.getElementById('u-category') || {}).value || '';
  const method = CREATION_METHODS[currentCreationType] || CREATION_METHODS['fresh'];
  const isImport = currentCreationType === 'import';
  const isBedrock = category === 'bedrock';

  const versionSelect = document.getElementById('u-version');
  const engineSelect = document.getElementById('u-engine');
  const categoryDesc = document.getElementById('u-category-desc');

  uVersionAvailability = {};
  hideEl('u-download-status-group');

  if (!category) {
    hideEl('u-engine-group');
    hideEl('u-version-group');
    hideEl('u-upload-jar-group');
    // Memory always applies to an import (its category comes from the archive)
    if (isImport) showEl('u-ram-group');
    else hideEl('u-ram-group');
    setPropsPanelVisible(false);
    if (categoryDesc) categoryDesc.textContent = 'Choose whether you want a Java or Bedrock server';
    validateUnifiedForm();
    return;
  }

  applyPropsEdition(category);
  setPropsPanelVisible(method.showProps);

  // Java needs RAM/JVM settings; Bedrock is a native binary
  if (isBedrock) hideEl('u-ram-group');
  else showEl('u-ram-group');

  // The version picker and custom-JAR upload only apply to a fresh Java build —
  // an import brings its own executable inside the ZIP.
  const needsVersionPicker = !isBedrock && !isImport;
  if (needsVersionPicker) showEl('u-upload-jar-group');
  else hideEl('u-upload-jar-group');

  if (category === 'unmodded') {
    hideEl('u-engine-group');
    if (categoryDesc) categoryDesc.textContent = 'Official Minecraft Java Edition server — no mods or plugins';
    if (needsVersionPicker) {
      showEl('u-version-group');
      loadUnifiedVersionsForEngine('vanilla');
    } else {
      hideEl('u-version-group');
    }
  } else if (category === 'modded') {
    showEl('u-engine-group');
    if (categoryDesc) categoryDesc.textContent = 'Java Edition server with plugin/mod support';
    hideEl('u-version-group');
    if (versionSelect) {
      versionSelect.innerHTML = '<option value="">Select server engine first...</option>';
      versionSelect.value = '';
      versionSelect.disabled = true;
    }
    if (engineSelect && engineSelect.value && needsVersionPicker) {
      // Keep an already-picked engine working when the user flips back
      showEl('u-version-group');
      loadUnifiedVersionsForEngine(engineSelect.value);
    }
  } else if (isBedrock) {
    hideEl('u-engine-group');
    hideEl('u-version-group');
    if (categoryDesc) categoryDesc.textContent = 'Official Minecraft Bedrock Edition server — the latest version is downloaded automatically';
    if (versionSelect) versionSelect.value = '';
  }

  // Sensible port/player defaults per edition, without clobbering user edits
  const portInput = document.getElementById('u-server-port');
  const playersInput = document.getElementById('u-max-players');
  if (portInput && (!portInput.value || portInput.value === '25565' || portInput.value === '19132')) {
    portInput.value = isBedrock ? '19132' : '25565';
  }
  if (playersInput && (!playersInput.value || playersInput.value === '20' || playersInput.value === '10')) {
    playersInput.value = isBedrock ? '10' : '20';
  }

  validateUnifiedForm();
}

function onUnifiedEngineChange() {
  const engineSelect = document.getElementById('u-engine');
  const versionSelect = document.getElementById('u-version');
  const engineDesc = document.getElementById('u-engine-desc');

  const serverEngine = engineSelect ? engineSelect.value : '';
  uVersionAvailability = {};
  hideEl('u-download-status-group');

  if (!serverEngine) {
    if (versionSelect) {
      versionSelect.innerHTML = '<option value="">Select server engine first...</option>';
      versionSelect.value = '';
      versionSelect.disabled = true;
    }
    hideEl('u-version-group');
    if (engineDesc) engineDesc.textContent = 'Select a server type';
    validateUnifiedForm();
    return;
  }

  const selectedOption = engineSelect.options[engineSelect.selectedIndex];
  if (engineDesc) engineDesc.textContent = selectedOption.dataset.description || '';

  // Import takes its JAR from the ZIP — no version download step
  if (currentCreationType !== 'import') {
    showEl('u-version-group');
    loadUnifiedVersionsForEngine(serverEngine);
  }
  validateUnifiedForm();
}

async function loadUnifiedEngines() {
  try {
    const result = await apiRequest('/api/jar-bucket/all-types');
    const allTypes = result.types || [];
    const moddedEngines = allTypes.filter(t => t.id !== 'vanilla' && (t.category === 'java' || t.category === 'modded'));
    
    const engineSelect = document.getElementById('u-engine');
    
    if (moddedEngines.length === 0) {
      engineSelect.innerHTML = '<option value="">No server types available</option>';
      engineSelect.disabled = true;
      return;
    }
    
    engineSelect.innerHTML = '<option value="">Select server engine...</option>';
    engineSelect.disabled = false;
    
    moddedEngines.forEach(engine => {
      const option = document.createElement('option');
      option.value = engine.id;
      option.textContent = `${engine.icon || '📦'} ${engine.name}`;
      option.dataset.description = engine.description || '';
      engineSelect.appendChild(option);
    });
  } catch (error) {
    console.error('Failed to load server engines:', error);
    const engineSelect = document.getElementById('u-engine');
    engineSelect.innerHTML = '<option value="">Error loading server engines</option>';
  }
}

async function loadUnifiedVersionsForEngine(serverEngine) {
  const versionSelect = document.getElementById('u-version');
  const versionStatus = document.getElementById('u-version-status');
  
  try {
    versionSelect.innerHTML = '<option value="">Loading versions...</option>';
    versionSelect.disabled = true;
    if (versionStatus) versionStatus.textContent = '';
    
    const result = await apiRequest(`/api/jar-bucket/all-versions/${serverEngine}`);
    const versions = result.versions || [];
    
    if (versions.length === 0) {
      versionSelect.innerHTML = '<option value="">No versions available</option>';
      validateUnifiedForm();
      return;
    }
    
    uVersionAvailability = {};
    versions.forEach(v => {
      uVersionAvailability[v.version] = { downloaded: v.downloaded };
    });
    
    versionSelect.innerHTML = '<option value="">Select version...</option>';
    versions.forEach(v => {
      const option = document.createElement('option');
      option.value = v.version;
      option.textContent = v.downloaded 
        ? `${v.version} ✓ (Downloaded)` 
        : v.version;
      option.dataset.downloaded = v.downloaded;
      versionSelect.appendChild(option);
    });
    versionSelect.disabled = false;
  } catch (error) {
    console.error('Failed to load versions:', error);
    versionSelect.innerHTML = '<option value="">Error loading versions</option>';
  }
  validateUnifiedForm();
}

function onUnifiedVersionChange() {
  const version = (document.getElementById('u-version') || {}).value || '';
  const versionStatus = document.getElementById('u-version-status');
  const versionDesc = document.getElementById('u-version-desc');

  hideEl('u-download-status-group');

  if (!version) {
    if (versionStatus) {
      versionStatus.textContent = '';
      versionStatus.className = 'version-status';
    }
    if (versionDesc) versionDesc.textContent = 'Select the Minecraft version';
    validateUnifiedForm();
    return;
  }

  const info = uVersionAvailability[version] || {};

  if (info.downloaded) {
    if (versionStatus) {
      versionStatus.textContent = '✓ Downloaded';
      versionStatus.className = 'version-status downloaded';
    }
    if (versionDesc) versionDesc.textContent = 'JAR file is already downloaded and ready to use';
  } else {
    if (versionStatus) {
      versionStatus.textContent = '⬇ Will Download';
      versionStatus.className = 'version-status not-downloaded';
    }
    if (versionDesc) versionDesc.textContent = 'JAR will be downloaded automatically when the server is created';
  }

  validateUnifiedForm();
}

function toggleUnifiedCustomJar() {
  const checkbox = document.getElementById('u-upload-jar');
  const versionGroup = document.getElementById('u-version-group');
  const useCustom = !!(checkbox && checkbox.checked);

  if (useCustom) showEl('u-custom-jar-upload');
  else hideEl('u-custom-jar-upload');

  // A custom JAR replaces the version download entirely
  if (versionGroup && currentCreationType === 'fresh') {
    const category = (document.getElementById('u-category') || {}).value || '';
    const showVersion = !useCustom && (category === 'unmodded' ||
      (category === 'modded' && (document.getElementById('u-engine') || {}).value));
    versionGroup.style.display = showVersion ? 'flex' : 'none';
  }

  validateUnifiedForm();
}

// ==================== Validation ====================

const uTouchedFields = new Set();

function isFieldVisible(id) {
  const el = document.getElementById(id);
  return !!(el && el.offsetParent !== null);
}

function setFieldError(id, message) {
  const input = document.getElementById(id);
  const errorEl = document.getElementById(`${id}-error`);
  const field = input ? input.closest('.form-field') : null;
  const show = !!message && uTouchedFields.has(id);

  if (errorEl) {
    errorEl.textContent = show ? message : '';
    errorEl.classList.toggle('show', show);
  }
  if (field) field.classList.toggle('has-error', show);
  if (input) {
    if (show) input.setAttribute('aria-invalid', 'true');
    else input.removeAttribute('aria-invalid');
  }
}

function clearAllUnifiedErrors() {
  document.querySelectorAll('#unified-server-form .field-error').forEach(el => {
    el.textContent = '';
    el.classList.remove('show');
  });
  document.querySelectorAll('#unified-server-form .form-field.has-error').forEach(el => {
    el.classList.remove('has-error');
  });
  document.querySelectorAll('#unified-server-form [aria-invalid]').forEach(el => {
    el.removeAttribute('aria-invalid');
  });
}

function intFieldError(id, label, min, max, { required = true } = {}) {
  if (!isFieldVisible(id)) return null;
  const el = document.getElementById(id);
  const raw = (el.value || '').trim();
  if (!raw) return required ? `${label} is required` : null;
  const value = Number(raw);
  if (!Number.isInteger(value)) return `${label} must be a whole number`;
  if (value < min || value > max) return `${label} must be between ${min} and ${max}`;
  return null;
}

/**
 * Validate everything currently on screen. Returns the list of error messages;
 * per-field messages are rendered for fields the user has already touched.
 */
function validateUnifiedForm() {
  if (!currentCreationType) return [];

  const value = id => ((document.getElementById(id) || {}).value || '').trim();
  const hasFile = id => {
    const el = document.getElementById(id);
    return !!(el && el.files && el.files.length);
  };

  const type = currentCreationType;
  const category = value('u-category');
  const isBedrock = category === 'bedrock';
  const useCustomJar = !!(document.getElementById('u-upload-jar') || {}).checked
    && isFieldVisible('u-upload-jar');

  const errors = {};

  // --- Left column: MServer configuration ---
  if (type !== 'import' && !value('u-name')) {
    errors['u-name'] = 'Give your server a name';
  }
  if (type !== 'import' && !category) {
    errors['u-category'] = 'Select a category';
  }
  if (category === 'modded' && isFieldVisible('u-engine') && !value('u-engine') && type !== 'import') {
    errors['u-engine'] = 'Select a server engine';
  }
  if (isFieldVisible('u-version') && !useCustomJar && !value('u-version')) {
    errors['u-version'] = 'Select a Minecraft version';
  }
  if (useCustomJar && !hasFile('u-jar-file')) {
    errors['u-jar-file'] = 'Choose a JAR file to upload';
  }
  if (type === 'import' && !hasFile('u-import-file')) {
    errors['u-import-file'] = 'Choose the server ZIP file to import';
  }
  if (type === 'import-world' && !hasFile('u-world-file')) {
    errors['u-world-file'] = 'Choose the world ZIP file to import';
  }
  if (isFieldVisible('u-min-ram')) {
    const toMb = raw => {
      const m = /^(\d+)([GM])$/i.exec(raw || '');
      if (!m) return null;
      return m[2].toUpperCase() === 'G' ? parseInt(m[1], 10) * 1024 : parseInt(m[1], 10);
    };
    const min = toMb(value('u-min-ram'));
    const max = toMb(value('u-max-ram'));
    if (min !== null && max !== null && min > max) {
      errors['u-min-ram'] = 'Min RAM cannot be larger than Max RAM';
    }
  }

  // --- Right column: server properties ---
  const numeric = [
    ['u-server-port', 'Server port', 1, 65535],
    ['u-max-players', 'Max players', 1, 100],
    ['u-view-distance', 'View distance', 4, 255],
    ['u-tick-distance', 'Tick distance', 4, 12],
    ['u-idle-timeout', 'Idle timeout', 0, 10080]
  ];
  numeric.forEach(([id, label, min, max]) => {
    const err = intFieldError(id, label, min, max);
    if (err) errors[id] = err;
  });

  if (isFieldVisible('u-generator-settings')) {
    const raw = value('u-generator-settings');
    if (raw && (raw.startsWith('{') || raw.startsWith('['))) {
      try {
        JSON.parse(raw);
      } catch (_) {
        errors['u-generator-settings'] = 'Generator settings is not valid JSON';
      }
    }
  }

  // Render per-field messages, then gate the submit button
  const trackedIds = ['u-name', 'u-category', 'u-engine', 'u-version', 'u-jar-file',
    'u-import-file', 'u-world-file', 'u-min-ram', 'u-server-port', 'u-max-players',
    'u-view-distance', 'u-tick-distance', 'u-idle-timeout', 'u-generator-settings'];
  trackedIds.forEach(id => setFieldError(id, errors[id] || ''));

  const messages = Object.values(errors);
  updateUnifiedSubmitState(messages);
  scheduleScrollHintRefresh();
  return messages;
}

function updateUnifiedSubmitState(messages) {
  const submitBtn = document.getElementById('u-submit-btn');
  const hint = document.getElementById('u-submit-hint');
  if (!submitBtn) return;
  if (submitBtn.dataset.busy === '1') return;   // never re-enable mid-submit

  const ok = !messages || messages.length === 0;
  submitBtn.disabled = !ok;
  if (hint) {
    if (ok) {
      hint.textContent = '';
    } else if (messages.length === 1) {
      hint.textContent = messages[0];
    } else {
      hint.textContent = `${messages.length} fields still need attention`;
    }
  }
}

// Live validation: mark a field touched once the user interacts with it, and
// re-check the whole form on every change so the submit button stays honest.
document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('unified-server-form');
  if (!form) return;

  form.addEventListener('input', e => {
    if (e.target.id) uTouchedFields.add(e.target.id);
    validateUnifiedForm();
  });
  form.addEventListener('change', e => {
    if (e.target.id) uTouchedFields.add(e.target.id);
    validateUnifiedForm();
  });
  form.addEventListener('blur', e => {
    if (e.target && e.target.id) {
      uTouchedFields.add(e.target.id);
      validateUnifiedForm();
    }
  }, true);

  // 'scroll' does not bubble — listen in the capture phase instead
  const modal = document.getElementById('server-modal');
  if (modal) modal.addEventListener('scroll', scheduleScrollHintRefresh, true);
  window.addEventListener('resize', scheduleScrollHintRefresh);

  initFieldTooltips();
});

// ==================== Help tooltips ====================

let uTooltipEl = null;
let uTooltipAnchor = null;

function initFieldTooltips() {
  if (uTooltipEl) return;

  uTooltipEl = document.createElement('div');
  uTooltipEl.className = 'mserver-tooltip';
  uTooltipEl.setAttribute('role', 'tooltip');
  document.body.appendChild(uTooltipEl);

  const show = target => {
    const tip = target.getAttribute('data-tip');
    if (!tip) return;
    uTooltipAnchor = target;
    uTooltipEl.textContent = tip;
    uTooltipEl.classList.add('show');
    positionTooltip(target);
  };
  const hide = () => {
    uTooltipAnchor = null;
    uTooltipEl.classList.remove('show');
  };

  document.addEventListener('mouseover', e => {
    const target = e.target.closest ? e.target.closest('.help-icon') : null;
    if (target) show(target);
  });
  document.addEventListener('mouseout', e => {
    const target = e.target.closest ? e.target.closest('.help-icon') : null;
    if (target && target === uTooltipAnchor) hide();
  });
  document.addEventListener('focusin', e => {
    const target = e.target.closest ? e.target.closest('.help-icon') : null;
    if (target) show(target);
  });
  document.addEventListener('focusout', hide);
  // Tap-to-toggle on touch devices (the icon is inside a <label>, so stop the
  // click from toggling the checkbox it belongs to)
  document.addEventListener('click', e => {
    const target = e.target.closest ? e.target.closest('.help-icon') : null;
    if (!target) {
      hide();
      return;
    }
    e.preventDefault();
    e.stopPropagation();
    if (uTooltipAnchor === target) hide();
    else show(target);
  });
  window.addEventListener('scroll', () => {
    if (uTooltipAnchor) positionTooltip(uTooltipAnchor);
  }, true);
  window.addEventListener('resize', hide);
}

function positionTooltip(anchor) {
  if (!uTooltipEl) return;
  const rect = anchor.getBoundingClientRect();
  const tip = uTooltipEl.getBoundingClientRect();
  const margin = 8;

  let left = rect.left + rect.width / 2 - tip.width / 2;
  left = Math.max(margin, Math.min(left, window.innerWidth - tip.width - margin));

  let top = rect.bottom + 6;
  if (top + tip.height > window.innerHeight - margin) {
    top = rect.top - tip.height - 6;
  }
  top = Math.max(margin, top);

  uTooltipEl.style.left = `${Math.round(left)}px`;
  uTooltipEl.style.top = `${Math.round(top)}px`;
}

// ==================== Unified Form Submit ====================

async function submitUnifiedForm(e) {
  e.preventDefault();

  // Belt-and-braces: the submit button is disabled while the form is invalid,
  // but a keyboard submit or a stale state should never slip past validation.
  const problems = validateUnifiedForm();
  if (problems.length) {
    document.querySelectorAll('#unified-server-form input, #unified-server-form select')
      .forEach(el => { if (el.id) uTouchedFields.add(el.id); });
    validateUnifiedForm();
    const firstBad = document.querySelector('#unified-server-form .form-field.has-error');
    if (firstBad) firstBad.scrollIntoView({ block: 'center', behavior: 'smooth' });
    showNotification(problems[0], 'error');
    return;
  }

  setUnifiedSubmitBusy(true);
  setWizardStep(3);

  try {
    if (currentCreationType === 'fresh') {
      await createFreshServer(e);
    } else if (currentCreationType === 'import') {
      await importServer(e);
    } else if (currentCreationType === 'import-world') {
      await importWorld(e);
    }
  } finally {
    setUnifiedSubmitBusy(false);
  }
}

// While a create/import is in flight the submit button is owned by the flow —
// the live validator must not flip it back on underneath.
function setUnifiedSubmitBusy(busy) {
  const submitBtn = document.getElementById('u-submit-btn');
  if (!submitBtn) return;
  if (busy) {
    submitBtn.dataset.busy = '1';
    submitBtn.disabled = true;
  } else {
    delete submitBtn.dataset.busy;
    if (currentCreationType) setWizardStep(2);
    validateUnifiedForm();
  }
}

/**
 * Build the server.properties payload from the properties column.
 * Booleans stay real booleans — the backend renders them as true/false.
 */
function collectUnifiedServerProperties(isBedrock) {
  const value = id => ((document.getElementById(id) || {}).value || '').trim();
  const checked = id => !!(document.getElementById(id) || {}).checked;
  const clampInt = (id, fallback, min, max) => {
    const parsed = parseInt(value(id), 10);
    return Number.isNaN(parsed) ? fallback : Math.min(max, Math.max(min, parsed));
  };

  const props = {
    'server-port': clampInt('u-server-port', isBedrock ? 19132 : 25565, 1, 65535),
    'max-players': clampInt('u-max-players', isBedrock ? 10 : 20, 1, 100),
    'gamemode': value('u-gamemode') || 'survival',
    'force-gamemode': checked('u-force-gamemode'),
    'difficulty': value('u-difficulty') || 'easy',
    'level-seed': value('u-level-seed')
  };

  if (isBedrock) {
    props['level-name'] = value('u-level-name') || 'Bedrock level';
    props['view-distance'] = clampInt('u-view-distance', 32, 4, 255);
    props['tick-distance'] = clampInt('u-tick-distance', 4, 4, 12);
    props['player-idle-timeout'] = clampInt('u-idle-timeout', 30, 0, 10080);
    props['allow-list'] = checked('u-allow-list');
    return props;
  }

  props['pvp'] = checked('u-pvp');
  props['hardcore'] = checked('u-hardcore');
  props['generate-structures'] = checked('u-generate-structures');
  props['spawn-npcs'] = checked('u-spawn-npcs');
  props['spawn-animals'] = checked('u-spawn-animals');
  props['spawn-monsters'] = checked('u-spawn-monsters');
  props['enable-command-block'] = checked('u-enable-command-block');

  // Only send the world generator settings when they differ from the vanilla
  // default — 'level-type' ids are namespaced from 1.16 onward, so leaving the
  // key out keeps older versions on their own default.
  const levelType = value('u-level-type');
  if (levelType && levelType !== 'minecraft:normal') props['level-type'] = levelType;
  const generatorSettings = value('u-generator-settings');
  if (generatorSettings) props['generator-settings'] = generatorSettings;

  return props;
}

// Create fresh server with JAR download
async function createFreshServer(e) {
  const name = document.getElementById('u-name').value;
  const category = document.getElementById('u-category').value;
  const isBedrock = category === 'bedrock';
  const serverEngine = isBedrock ? 'bedrock' : (category === 'modded' 
    ? document.getElementById('u-engine').value 
    : 'vanilla');
  const version = isBedrock ? 'latest' : document.getElementById('u-version').value;
  const executable = isBedrock ? 'server.sh' : 'server.jar';
  const minRam = document.getElementById('u-min-ram').value;
  const maxRam = document.getElementById('u-max-ram').value;
  const extraJvmArgs = document.getElementById('u-jvm-args').value.trim();
  const javaArgs = isBedrock ? '' : `-Xms${minRam} -Xmx${maxRam}${extraJvmArgs ? ' ' + extraJvmArgs : ''}`;
  const uploadCustom = !isBedrock && document.getElementById('u-upload-jar').checked;
  
  // Server properties (the whole right-hand column, per edition)
  const serverProperties = collectUnifiedServerProperties(isBedrock);

  const versionInfo = uVersionAvailability[version] || {};
  const needsDownload = !isBedrock && !versionInfo.downloaded;
  
  if (!category) {
    showNotification('Please select a category', 'error');
    return;
  }
  
  if (category === 'modded' && !serverEngine) {
    showNotification('Please select a server engine', 'error');
    return;
  }
  
  if (!isBedrock && !uploadCustom && !version) {
    showNotification('Please select a version', 'error');
    return;
  }
  
  // Get UI elements
  const submitBtn = document.getElementById('u-submit-btn');
  const backBtn = e.target.querySelector('.btn:not([type="submit"])');
  const originalText = submitBtn.textContent;
  const downloadStatusGroup = document.getElementById('u-download-status-group');
  const downloadProgress = document.querySelector('#u-jar-download-status .download-progress');
  const progressFill = document.querySelector('#u-jar-download-status .progress-fill');
  const progressText = document.querySelector('#u-jar-download-status .progress-text');
  const downloadInfo = document.querySelector('#u-jar-download-status .download-info');
  
  if (progressFill) progressFill.style.width = '0%';
  if (progressText) progressText.textContent = '0%';
  if (downloadProgress) downloadProgress.style.display = 'none';
  if (downloadStatusGroup) downloadStatusGroup.style.display = 'none';
  
  const updateProgress = (message, percent = null, isError = false) => {
    showUnifiedStatusGroup();
    if (downloadInfo) {
      const icon = isError ? '❌' : (percent === 100 ? '✓' : '⏳');
      downloadInfo.innerHTML = `<span class="info-icon">${icon}</span> ${message}`;
      if (isError) downloadInfo.classList.add('error');
      else downloadInfo.classList.remove('error');
    }
    if (percent !== null && downloadProgress) {
      downloadProgress.style.display = 'flex';
      if (progressFill) progressFill.style.width = `${percent}%`;
      if (progressText) progressText.textContent = `${Math.round(percent)}%`;
    }
  };
  
  const resetOnError = (errorMsg) => {
    submitBtn.textContent = originalText;
    submitBtn.disabled = false;
    if (backBtn) backBtn.disabled = false;
    updateProgress(errorMsg, null, true);
    showNotification(errorMsg, 'error');
  };
  
  try {
    submitBtn.textContent = 'Creating...';
    submitBtn.disabled = true;
    if (backBtn) backBtn.disabled = true;
    
    if (isBedrock) {
      // Bedrock step-by-step creation flow
      const bedrockStatusEl = document.getElementById('u-bedrock-setup-status');
      const jarStatusEl = document.getElementById('u-jar-download-status');
      showUnifiedStatusGroup();
      if (bedrockStatusEl) bedrockStatusEl.style.display = 'block';
      if (jarStatusEl) jarStatusEl.style.display = 'none';

      for (let i = 1; i <= 5; i++) {
        const stepEl = document.getElementById(`bstep-${i}`);
        if (stepEl) {
          stepEl.dataset.state = 'pending';
          stepEl.querySelector('.bstep-icon').textContent = '○';
        }
      }
      const bstepFill = document.querySelector('#bstep-2 .bstep-fill');
      const bstepPct = document.querySelector('#bstep-2 .bstep-pct');
      if (bstepFill) bstepFill.style.width = '0%';
      if (bstepPct) bstepPct.textContent = '0%';

      const advanceToStep = (stepNum, labelText = null) => {
        for (let i = 1; i < stepNum; i++) {
          const el = document.getElementById(`bstep-${i}`);
          if (el && el.dataset.state !== 'done' && el.dataset.state !== 'error') {
            el.dataset.state = 'done';
            el.querySelector('.bstep-icon').textContent = '✓';
          }
        }
        const el = document.getElementById(`bstep-${stepNum}`);
        if (el && el.dataset.state !== 'done') {
          el.dataset.state = 'active';
          el.querySelector('.bstep-icon').textContent = '⏳';
          if (labelText) el.querySelector('.bstep-label').textContent = labelText;
        }
      };

      const failAtCurrentStep = (errMsg) => {
        for (let i = 1; i <= 5; i++) {
          const el = document.getElementById(`bstep-${i}`);
          if (el && el.dataset.state === 'active') {
            el.dataset.state = 'error';
            el.querySelector('.bstep-icon').textContent = '✗';
            break;
          }
        }
        submitBtn.textContent = originalText;
        submitBtn.disabled = false;
        if (backBtn) backBtn.disabled = false;
        showNotification(errMsg, 'error');
      };

      try {
        advanceToStep(1);
        submitBtn.textContent = 'Creating...';

        const result = await apiRequest('/api/servers', {
          method: 'POST',
          body: JSON.stringify({
            name,
            executable: 'server.sh',
            javaArgs: '',
            category: 'bedrock',
            serverEngine: 'bedrock',
            serverType: 'bedrock',
            version: 'latest',
            // Bedrock's server.properties is written later by setup-bedrock, but
            // send the port now so create_server's duplicate-port check runs and
            // a clash is caught before anything is created (issue #44). The rest
            // of the properties still go to setup-bedrock.
            serverProperties: { 'server-port': serverProperties['server-port'] }
          })
        });

        if (result.pendingApproval) {
          advanceToStep(1);
          const el1 = document.getElementById('bstep-1');
          if (el1) { el1.dataset.state = 'done'; el1.querySelector('.bstep-icon').textContent = '✓'; }
          showNotification('Server created and pending admin approval', 'info');
          closeServerModal();
          await loadServers();
          return;
        }

        advanceToStep(2, 'Downloading latest Bedrock server...');
        submitBtn.textContent = 'Downloading...';

        let setupResult;
        try {
          setupResult = await apiRequest(`/api/servers/${result.serverId}/setup-bedrock`, {
            method: 'POST',
            body: JSON.stringify({
              serverName: name,
              serverProperties
            })
          });
        } catch (setupErr) {
          failAtCurrentStep(`Failed to start Bedrock download: ${setupErr.message}`);
          return;
        }

        if (!setupResult.progressId) {
          failAtCurrentStep('Failed to start Bedrock download — no progress ID returned');
          return;
        }

        const progressId = setupResult.progressId;
        let setupComplete = false;
        let pollCount = 0;
        const maxPolls = 720;
        let lastStep = 2;

        while (!setupComplete && pollCount < maxPolls) {
          await new Promise(r => setTimeout(r, 500));
          pollCount++;

          try {
            const progress = await apiRequest(`/api/jar-bucket/progress/${progressId}`);
            const step = progress.step || lastStep;

            if (step > lastStep) {
              lastStep = step;
              if (step === 3) {
                advanceToStep(3, 'Extracting server files...');
                submitBtn.textContent = 'Extracting...';
              } else if (step === 4) {
                advanceToStep(4, 'Writing server.properties...');
                submitBtn.textContent = 'Configuring...';
              }
            }

            if (step === 2 && progress.progress != null) {
              const pct = progress.progress;
              if (bstepFill) bstepFill.style.width = `${pct}%`;
              if (bstepPct) bstepPct.textContent = `${Math.round(pct)}%`;
            }

            if (progress.status === 'complete') {
              for (let i = 1; i <= 5; i++) {
                const el = document.getElementById(`bstep-${i}`);
                if (el) { el.dataset.state = 'done'; el.querySelector('.bstep-icon').textContent = '✓'; }
              }
              setupComplete = true;
            } else if (progress.status === 'error') {
              failAtCurrentStep(progress.error || 'Bedrock setup failed');
              return;
            }
          } catch (pollErr) {
            console.error('Progress poll error:', pollErr);
          }
        }

        if (!setupComplete) {
          failAtCurrentStep('Bedrock setup timed out');
          return;
        }

        await new Promise(r => setTimeout(r, 800));
        await loadServers();
        selectServer(result.serverId);
        closeServerModal();
        showNotification('Bedrock server created successfully!', 'success');

      } catch (error) {
        failAtCurrentStep(error.message || 'Failed to create Bedrock server');
      }

    } else if (uploadCustom) {
      const fileInput = document.getElementById('u-jar-file');
      if (!fileInput.files.length) {
        resetOnError('Please select a JAR file to upload');
        return;
      }
      
      updateProgress('Creating server...', 10);
      
      const result = await apiRequest('/api/servers', {
        method: 'POST',
        body: JSON.stringify({
          name,
          executable,
          javaArgs,
          category,
          serverEngine: 'custom',
          serverProperties
        })
      });
      
      if (result.pendingApproval) {
        showNotification('Server created and pending admin approval', 'info');
        closeServerModal();
        await loadServers();
        return;
      }
      
      updateProgress('Uploading JAR file...', 50);
      
      const formData = new FormData();
      formData.append('file', fileInput.files[0]);
      
      const uploadResponse = await fetch(`/api/servers/${result.serverId}/upload-jar`, {
        method: 'POST',
        headers: window.csrfToken ? { 'X-CSRF-Token': window.csrfToken } : {},
        body: formData
      });
      
      if (!uploadResponse.ok) {
        const errorData = await uploadResponse.json().catch(() => ({}));
        throw new Error(errorData.error || 'Failed to upload JAR file');
      }
      
      updateProgress('Server created successfully!', 100);
      await new Promise(r => setTimeout(r, 1000));
      
      await loadServers();
      selectServer(result.serverId);
      closeServerModal();
      
    } else if (needsDownload) {
      updateProgress(`Downloading ${serverEngine} ${version}...`, 0);
      submitBtn.textContent = 'Downloading JAR...';
      
      let downloadResult;
      try {
        downloadResult = await apiRequest('/api/jar-bucket/download', {
          method: 'POST',
          body: JSON.stringify({ type: serverEngine, version })
        });
      } catch (downloadErr) {
        resetOnError(`Failed to start download: ${downloadErr.message}`);
        return;
      }
      
      if (!downloadResult.progressId) {
        resetOnError('Failed to start download - no progress ID returned');
        return;
      }

      const progressId = downloadResult.progressId;
      let downloadComplete = false;
      let downloadError = null;
      let pollCount = 0;
      const maxPolls = 600;
      
      while (!downloadComplete && pollCount < maxPolls) {
        await new Promise(r => setTimeout(r, 500));
        pollCount++;
        
        try {
          const progress = await apiRequest(`/api/jar-bucket/progress/${progressId}`);
          
          if (progress.status === 'downloading') {
            const pct = progress.progress || 0;
            const downloaded = formatBytes(progress.downloaded || 0);
            const total = formatBytes(progress.total || 0);
            updateProgress(`Downloading ${serverEngine} ${version}... (${downloaded} / ${total})`, pct);
          } else if (progress.status === 'complete') {
            downloadComplete = true;
            if (progress.success === false) {
              downloadError = progress.error || 'Download failed';
            } else {
              updateProgress('Download complete!', 100);
            }
          } else if (progress.status === 'error') {
            downloadComplete = true;
            downloadError = progress.error || 'Download failed';
          }
        } catch (pollErr) {
          console.error('Error polling download progress:', pollErr);
        }
      }
      
      if (!downloadComplete) {
        resetOnError('Download timed out. Please try again.');
        return;
      }
      
      if (downloadError) {
        resetOnError(`Download failed: ${downloadError}`);
        return;
      }
      
      submitBtn.textContent = 'Creating Server...';
      updateProgress('Creating server files...', 0);
      
      let result;
      try {
        result = await apiRequest('/api/servers', {
          method: 'POST',
          body: JSON.stringify({
            name,
            executable,
            javaArgs,
            category,
            serverEngine,
            version,
            downloadJar: true,
            serverProperties
          })
        });
      } catch (createErr) {
        resetOnError(`Failed to create server: ${createErr.message}`);
        return;
      }
      
      if (result.pendingApproval) {
        updateProgress('Server created and pending admin approval', 100);
        showNotification('Server created and pending admin approval', 'info');
        await new Promise(r => setTimeout(r, 1500));
        closeServerModal();
        await loadServers();
      } else if (result.warning) {
        updateProgress(`Server created with warning: ${result.warning}`, 100);
        showNotification(result.warning, 'warning');
        await new Promise(r => setTimeout(r, 1500));
        await loadServers();
        selectServer(result.serverId);
        closeServerModal();
      } else {
        updateProgress('Server created successfully!', 100);
        showNotification('Server created successfully!', 'success');
        await new Promise(r => setTimeout(r, 1000));
        await loadServers();
        selectServer(result.serverId);
        closeServerModal();
      }
      
    } else {
      // Use existing local JAR
      updateProgress('Creating server files...', 20);
      
      let result;
      try {
        result = await apiRequest('/api/servers', {
          method: 'POST',
          body: JSON.stringify({
            name,
            executable,
            javaArgs,
            category,
            serverEngine,
            version,
            downloadJar: true,
            serverProperties
          })
        });
      } catch (createErr) {
        resetOnError(`Failed to create server: ${createErr.message}`);
        return;
      }
      
      if (result.pendingApproval) {
        updateProgress('Server created and pending admin approval', 100);
        showNotification('Server created and pending admin approval', 'info');
        await new Promise(r => setTimeout(r, 1500));
        closeServerModal();
        await loadServers();
      } else if (result.warning) {
        updateProgress(`Server created with warning: ${result.warning}`, 100);
        showNotification(result.warning, 'warning');
        await new Promise(r => setTimeout(r, 1500));
        await loadServers();
        selectServer(result.serverId);
        closeServerModal();
      } else {
        updateProgress('Server created successfully!', 100);
        showNotification('Server created successfully!', 'success');
        await new Promise(r => setTimeout(r, 1000));
        await loadServers();
        selectServer(result.serverId);
        closeServerModal();
      }
    }
    
    submitBtn.textContent = originalText;
    submitBtn.disabled = false;
    if (backBtn) backBtn.disabled = false;
    
  } catch (error) {
    console.error('Failed to create server:', error);
    resetOnError(`Failed to create server: ${error.message}`);
  }
}

// Import server from ZIP (unified)
async function importServer(e) {
  const name = document.getElementById('u-name').value.trim();
  const fileInput = document.getElementById('u-import-file');
  const executableName = document.getElementById('u-import-executable').value.trim();
  const category = document.getElementById('u-category').value;
  const engine = category === 'modded' ? document.getElementById('u-engine').value : 
                 (category === 'bedrock' ? 'Bedrock' : 'Vanilla');
  const minRam = document.getElementById('u-min-ram').value;
  const maxRam = document.getElementById('u-max-ram').value;
  const extraJvmArgs = document.getElementById('u-jvm-args').value.trim();
  const javaArgs = `-Xms${minRam} -Xmx${maxRam}${extraJvmArgs ? ' ' + extraJvmArgs : ''}`;
  
  if (!fileInput.files.length) {
    showNotification('Please select a ZIP file to import', 'error');
    return;
  }
  
  try {
    const submitBtn = document.getElementById('u-submit-btn');
    const originalText = submitBtn.textContent;
    submitBtn.textContent = 'Importing...';
    submitBtn.disabled = true;
    
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    // Only send non-empty fields — empty means "use managed.conf"
    if (name) formData.append('name', name);
    if (executableName) formData.append('executableName', executableName);
    formData.append('javaArgs', javaArgs);
    if (category) formData.append('category', category);
    if (engine) formData.append('engine', engine);
    // No server.properties values are sent on import: the archive's own
    // managed.conf / server.properties are authoritative and are edited
    // post-import, which is why the properties column is hidden for this flow.

    const response = await fetch('/api/servers/import', {
      method: 'POST',
      headers: window.csrfToken ? { 'X-CSRF-Token': window.csrfToken } : {},
      body: formData
    });
    
    if (!response.ok) {
      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        const errResult = await response.json();
        throw new Error(errResult.error || `Import failed (${response.status})`);
      } else if (response.status === 413) {
        throw new Error('File too large — please reduce the ZIP size and try again');
      } else {
        throw new Error(`Import failed (HTTP ${response.status})`);
      }
    }
    
    const result = await response.json();
    
    if (result.pendingApproval) {
      showNotification('Server imported and pending admin approval', 'info');
    } else {
      await loadServers();
      selectServer(result.serverId);
    }
    
    closeServerModal();
    submitBtn.textContent = originalText;
    submitBtn.disabled = false;
  } catch (error) {
    console.error('Failed to import server:', error);
    showNotification('Failed to import server: ' + error.message, 'error');
    const submitBtn = document.getElementById('u-submit-btn');
    submitBtn.textContent = 'Import Server';
    submitBtn.disabled = false;
  }
}

// Import world (unified)
async function importWorld(e) {
  const name = document.getElementById('u-name').value;
  const category = document.getElementById('u-category').value;
  const serverEngine = category === 'modded'
    ? document.getElementById('u-engine').value
    : 'vanilla';
  const version = document.getElementById('u-version').value;
  const worldFileInput = document.getElementById('u-world-file');
  const minRam = document.getElementById('u-min-ram').value;
  const maxRam = document.getElementById('u-max-ram').value;
  const extraJvmArgs = document.getElementById('u-jvm-args').value.trim();
  const javaArgs = `-Xms${minRam} -Xmx${maxRam}${extraJvmArgs ? ' ' + extraJvmArgs : ''}`;
  // World import is Java-only, so the Java property set always applies here.
  const serverProperties = collectUnifiedServerProperties(false);

  if (!category) { showNotification('Please select a category', 'error'); return; }
  if (category === 'modded' && !serverEngine) { showNotification('Please select a server engine', 'error'); return; }
  if (!version) { showNotification('Please select a version', 'error'); return; }
  if (!worldFileInput.files.length) { showNotification('Please select a world ZIP file', 'error'); return; }

  const submitBtn = document.getElementById('u-submit-btn');
  const backBtn = e.target.querySelector('.btn:not([type="submit"])');
  const originalText = submitBtn.textContent;
  submitBtn.textContent = 'Working...';
  submitBtn.disabled = true;
  if (backBtn) backBtn.disabled = true;

  const downloadStatusGroup = document.getElementById('u-download-status-group');
  const downloadProgress = document.querySelector('#u-jar-download-status .download-progress');
  const progressFill = document.querySelector('#u-jar-download-status .progress-fill');
  const progressText = document.querySelector('#u-jar-download-status .progress-text');
  const downloadInfo = document.querySelector('#u-jar-download-status .download-info');

  const updateProgress = (message, percent = null, isError = false) => {
    showUnifiedStatusGroup();
    if (downloadInfo) {
      const icon = isError ? '❌' : (percent === 100 ? '✓' : '⏳');
      downloadInfo.innerHTML = `<span class="info-icon">${icon}</span> ${message}`;
      if (isError) downloadInfo.classList.add('error');
      else downloadInfo.classList.remove('error');
    }
    if (percent !== null && downloadProgress) {
      downloadProgress.style.display = 'flex';
      if (progressFill) progressFill.style.width = `${percent}%`;
      if (progressText) progressText.textContent = `${Math.round(percent)}%`;
    }
  };

  const resetOnError = (msg) => {
    submitBtn.textContent = originalText;
    submitBtn.disabled = false;
    if (backBtn) backBtn.disabled = false;
    updateProgress(msg, null, true);
    showNotification(msg, 'error');
  };

  try {
    // Step 1: Download JAR if not already available
    const versionInfo = uVersionAvailability[version] || {};
    if (!versionInfo.downloaded) {
      updateProgress(`Downloading ${serverEngine} ${version}...`, 0);
      submitBtn.textContent = 'Downloading JAR...';

      let downloadResult;
      try {
        downloadResult = await apiRequest('/api/jar-bucket/download', {
          method: 'POST',
          body: JSON.stringify({ type: serverEngine, version })
        });
      } catch (err) {
        resetOnError(`Failed to start download: ${err.message}`);
        return;
      }

      if (!downloadResult.progressId) {
        resetOnError('Failed to start download — no progress ID returned');
        return;
      }

      const progressId = downloadResult.progressId;
      let done = false;
      let dlError = null;
      let polls = 0;

      while (!done && polls < 600) {
        await new Promise(r => setTimeout(r, 500));
        polls++;
        try {
          const progress = await apiRequest(`/api/jar-bucket/progress/${progressId}`);
          if (progress.status === 'downloading') {
            const pct = progress.progress || 0;
            const dl = formatBytes(progress.downloaded || 0);
            const tot = formatBytes(progress.total || 0);
            updateProgress(`Downloading ${serverEngine} ${version}... (${dl} / ${tot})`, pct);
          } else if (progress.status === 'complete') {
            done = true;
            if (progress.success === false) dlError = progress.error || 'Download failed';
            else updateProgress('Download complete!', 100);
          } else if (progress.status === 'error') {
            done = true;
            dlError = progress.error || 'Download failed';
          }
        } catch (_) { /* keep polling */ }
      }

      if (!done) { resetOnError('Download timed out. Please try again.'); return; }
      if (dlError) { resetOnError(`Download failed: ${dlError}`); return; }
    }

    // Step 2: Create the fresh server
    submitBtn.textContent = 'Creating Server...';
    updateProgress('Creating server files...', 0);

    let serverResult;
    try {
      serverResult = await apiRequest('/api/servers', {
        method: 'POST',
        body: JSON.stringify({
          name,
          executable: 'server.jar',
          javaArgs,
          category,
          serverEngine,
          version,
          downloadJar: true,
          serverProperties
        })
      });
    } catch (err) {
      resetOnError(`Failed to create server: ${err.message}`);
      return;
    }

    if (serverResult.pendingApproval) {
      updateProgress('Server created and pending admin approval', 100);
      showNotification('Server created and pending admin approval', 'info');
      await new Promise(r => setTimeout(r, 1500));
      closeServerModal();
      await loadServers();
      return;
    }

    // Step 3: Upload and import the world ZIP
    submitBtn.textContent = 'Importing World...';
    updateProgress('Uploading and importing world data...', 50);

    const formData = new FormData();
    formData.append('file', worldFileInput.files[0]);

    const worldResponse = await fetch(`/api/servers/${serverResult.serverId}/import-world`, {
      method: 'POST',
      headers: window.csrfToken ? { 'X-CSRF-Token': window.csrfToken } : {},
      body: formData
    });

    const worldResult = await worldResponse.json();

    if (!worldResponse.ok) {
      console.error('World import failed:', worldResult.error);
      await loadServers();
      selectServer(serverResult.serverId);
      closeServerModal();
      showNotification(`Server created but world import failed: ${worldResult.error}`, 'warning');
    } else {
      updateProgress('Server created with world!', 100);
      await new Promise(r => setTimeout(r, 800));
      await loadServers();
      selectServer(serverResult.serverId);
      closeServerModal();
      showNotification('Server created and world imported successfully!', 'success');
    }

  } catch (error) {
    console.error('Failed to import world:', error);
    resetOnError(`Failed: ${error.message}`);
  }
}

async function openEditServerModal() {
  if (!currentServerId) return;
  
  try {
    const server = await apiRequest(`/api/servers/${currentServerId}`);
    
    editingServerId = currentServerId;
    currentCreationType = null;

    document.getElementById('modal-title').textContent = 'Edit Server';
    setModalSubtitle(`Editing “${server.name || 'server'}”`);

    // Edit mode skips the wizard entirely — only the config form is shown
    const wizardSteps = document.getElementById('wizard-steps');
    if (wizardSteps) wizardSteps.style.display = 'none';
    document.getElementById('creation-type-section').style.display = 'none';
    document.getElementById('unified-server-form').style.display = 'none';
    document.getElementById('manual-server-form').style.display = 'flex';

    // Hide the back button in edit mode
    document.querySelector('#manual-server-form .back-btn').style.display = 'none';
    
    document.getElementById('input-name').value = server.name || '';
    document.getElementById('input-path').value = server.serverPath || '';
    document.getElementById('input-category').value = server.category || 'unmodded';
    
    // Parse RAM values and extra JVM args from javaArgs
    const javaArgs = server.javaArgs || '-Xms1G -Xmx2G';
    const minRamMatch = javaArgs.match(/-Xms(\d+[GMK])/i);
    const maxRamMatch = javaArgs.match(/-Xmx(\d+[GMK])/i);
    
    // Extract extra JVM args (everything except -Xms and -Xmx)
    const extraArgs = javaArgs
      .replace(/-Xms\d+[GMK]/gi, '')
      .replace(/-Xmx\d+[GMK]/gi, '')
      .trim();
    
    document.getElementById('input-min-ram').value = minRamMatch ? minRamMatch[1] : '1G';
    document.getElementById('input-max-ram').value = maxRamMatch ? maxRamMatch[1] : '2G';
    document.getElementById('input-jvm-args').value = extraArgs;
    // Show version management section and load current version + AutoStart from managed.conf
    const versionSection = document.getElementById('version-management-section');
    const versionDisplay = document.getElementById('current-version-display');
    
    // Default autoStart from config.json; may be overridden by managed.conf below
    document.getElementById('input-auto-start').checked = !!server.autoStart;
    
    if (versionSection && versionDisplay) {
      versionSection.style.display = 'block';
      versionDisplay.textContent = 'Loading...';
      
      // Load current version and AutoStart from managed.conf
      try {
        const managedData = await apiRequest(`/api/servers/${currentServerId}/managed`);
        if (managedData.managed && managedData.data) {
          if (managedData.data.Version) {
            versionDisplay.textContent = managedData.data.Version;
            versionDisplay.style.color = '#4CAF50';
          } else if (server.version) {
            versionDisplay.textContent = server.version;
            versionDisplay.style.color = '#FF9800';
          } else {
            versionDisplay.textContent = 'Unknown';
            versionDisplay.style.color = '#888';
          }
          // Sync AutoStart from managed.conf (it is the master)
          if (managedData.data.AutoStart !== undefined) {
            document.getElementById('input-auto-start').checked = managedData.data.AutoStart.toLowerCase() === 'true';
          }
        } else if (server.version) {
          versionDisplay.textContent = server.version;
          versionDisplay.style.color = '#FF9800';
        } else {
          versionDisplay.textContent = 'Unknown';
          versionDisplay.style.color = '#888';
        }
      } catch (err) {
        console.error('Failed to load version:', err);
        versionDisplay.textContent = server.version || 'Unknown';
        versionDisplay.style.color = '#FF9800';
      }
    }
    
    document.getElementById('server-modal').classList.add('active');
    scheduleScrollHintRefresh();
  } catch (error) {
    console.error('Failed to load server for editing:', error);
  }
}

function closeServerModal() {
  document.getElementById('server-modal').classList.remove('active');
  editingServerId = null;
  currentCreationType = null;

  // Hide version management section when closing
  const versionSection = document.getElementById('version-management-section');
  if (versionSection) {
    versionSection.style.display = 'none';
  }

  // Leave the wizard in a clean state for the next open
  const backBtn = document.querySelector('#manual-server-form .back-btn');
  if (backBtn) backBtn.style.display = '';
  clearCreationTypeSelection();
  setUnifiedSubmitBusy(false);
}

// ==================== Version Change Modal ====================

let versionChangeData = {
  currentVersion: null,
  currentEngine: null,
  availableVersions: []
};

async function openVersionChangeModal() {
  if (!currentServerId) return;
  
  try {
    // Get server info
    const server = await apiRequest(`/api/servers/${currentServerId}`);
    const managedData = await apiRequest(`/api/servers/${currentServerId}/managed`);
    
    // Get current version and engine
    const currentVersion = managedData.data?.Version || server.version || 'Unknown';
    const currentEngine = managedData.data?.Engine || server.serverType || 'Unknown';
    
    versionChangeData.currentVersion = currentVersion;
    versionChangeData.currentEngine = currentEngine;
    
    // Display current info
    document.getElementById('vc-current-version').textContent = currentVersion;
    document.getElementById('vc-server-engine').textContent = currentEngine;
    
    // Load available versions for the current engine
    const versionSelect = document.getElementById('vc-new-version');
    versionSelect.innerHTML = '<option value="">Loading versions...</option>';
    versionSelect.disabled = true;
    
    // Reset warning and backup option
    document.getElementById('vc-warning').style.display = 'none';
    document.getElementById('vc-backup-option').style.display = 'none';
    document.getElementById('vc-submit-btn').disabled = true;
    
    // Determine the engine key for API call
    let engineKey = currentEngine.toLowerCase();
    if (engineKey === 'vanilla') engineKey = 'vanilla';
    
    // Load versions from JAR Bucket
    try {
      const versionsResult = await apiRequest(`/api/jar-bucket/versions/${engineKey}`);
      const versions = versionsResult.versions || [];
      
      versionChangeData.availableVersions = versions;
      
      versionSelect.innerHTML = '<option value="">Select a version...</option>';
      versions.forEach(ver => {
        const option = document.createElement('option');
        option.value = ver;
        option.textContent = ver;
        if (ver === currentVersion) {
          option.textContent += ' (Current)';
          option.disabled = true;
        }
        versionSelect.appendChild(option);
      });
      versionSelect.disabled = false;
    } catch (err) {
      console.error('Failed to load versions:', err);
      versionSelect.innerHTML = '<option value="">Error loading versions</option>';
    }
    
    // Show modal
    document.getElementById('version-change-modal').classList.add('active');
  } catch (error) {
    console.error('Failed to open version change modal:', error);
    showNotification('Failed to load version information', 'error');
  }
}

function closeVersionChangeModal() {
  document.getElementById('version-change-modal').classList.remove('active');
  versionChangeData = {
    currentVersion: null,
    currentEngine: null,
    availableVersions: []
  };
}

function onVersionChangeSelection() {
  const newVersion = document.getElementById('vc-new-version').value;
  const warningDiv = document.getElementById('vc-warning');
  const backupOption = document.getElementById('vc-backup-option');
  const submitBtn = document.getElementById('vc-submit-btn');
  
  if (!newVersion) {
    warningDiv.style.display = 'none';
    backupOption.style.display = 'none';
    submitBtn.disabled = true;
    return;
  }
  
  const current = versionChangeData.currentVersion;
  
  // Era classification: legacy (<=1.21.x) vs modern (26.1+ / new world format).
  const currentModern = !isVersionBelow126(current);
  const newModern = !isVersionBelow126(newVersion);
  const cmp = compareVersions(newVersion, current);

  // Modern -> Legacy is not possible: the modern world format is one-way.
  if (currentModern && !newModern) {
    warningDiv.className = 'version-warning downgrade';
    warningDiv.innerHTML = `
      <strong>⚠️ Downgrade to a Legacy Version Not Possible</strong>
      <p>You cannot move ${current} back to ${newVersion}.</p>
      <p><strong>Reason:</strong> Minecraft's modern (26.1+) world storage format is not backwards-compatible. Downgrading to a legacy version is not supported and would corrupt the world. Create a new server if you need a legacy version.</p>
    `;
    warningDiv.style.display = 'block';
    backupOption.style.display = 'none';
    submitBtn.disabled = true;
    return;
  }

  let warningHtml = '';
  if (!currentModern && newModern) {
    // Legacy -> Modern: the ONLY case that shows the one-way conversion notice.
    warningDiv.className = 'version-warning upgrade';
    warningHtml = `
      <strong>⬆️ Upgrading to a Modern Version</strong>
      <p>You are upgrading from ${current} to ${newVersion}.</p>
      <p><strong>📦 World Storage Changes:</strong> Minecraft 26.1+ uses a new world storage format. Your world will be automatically converted, but this process is one-way and cannot be undone.</p>
    `;
  } else if (cmp > 0) {
    // Same-generation upgrade: no conversion notice needed.
    warningDiv.className = 'version-warning upgrade';
    warningHtml = `
      <strong>⬆️ Upgrading Version</strong>
      <p>You are upgrading from ${current} to ${newVersion}.</p>
    `;
  } else if (cmp < 0) {
    // Same-generation downgrade: warn about feature differences / corruption.
    warningDiv.className = 'version-warning downgrade';
    warningHtml = `
      <strong>⚠️ Downgrading Version</strong>
      <p>You are downgrading from ${current} to ${newVersion}.</p>
      <p><strong>Warning:</strong> Newer world data and features may be incompatible with the older version and can cause feature loss or world corruption. Proceed with caution.</p>
    `;
  } else {
    // Same version selected.
    warningDiv.className = 'version-warning';
    warningHtml = `<p>This is the version your server is already running.</p>`;
  }

  // A backup is ALWAYS taken automatically before the change (enforced server-side).
  warningHtml += `<p>🛟 A backup will be created automatically before the version is changed.</p>`;
  warningDiv.innerHTML = warningHtml;
  warningDiv.style.display = 'block';
  backupOption.style.display = 'none';

  submitBtn.disabled = false;
}

function parseMcVersionTuple(v) {
  // Mirrors server.py's _parse_mc_version_tuple: strip a modloader suffix
  // (e.g. '1.21.3-53.0.26' -> '1.21.3', '1.20.5-pre1' -> '1.20.5') before
  // pulling out up to 3 numeric groups. Unlike a single leading-run regex,
  // this doesn't get confused by weekly snapshot ids like '24w14a'.
  const base = String(v).split('-')[0];
  const parts = (base.match(/\d+/g) || []).map(Number).slice(0, 3);
  while (parts.length < 3) parts.push(0);
  return parts;
}

function compareVersions(v1, v2) {
  // Enhanced version comparison for Minecraft versioning
  // Handles both old (1.20.4) and new (26.1) numbering systems, plus
  // pre-release/RC/modloader suffixes (e.g. '1.20.5-pre1', '1.20.1-47.2.0')
  const t1 = parseMcVersionTuple(v1);
  const t2 = parseMcVersionTuple(v2);

  for (let i = 0; i < 3; i++) {
    if (t1[i] > t2[i]) return 1;
    if (t1[i] < t2[i]) return -1;
  }
  return 0;
}

function isVersionBelow126(version) {
  // Check if a version predates 26.1 (i.e. NOT in the modern/26.1+ world
  // format era). Mirrors server.py's mc_version_is_modern (inverted) so the
  // client-side warning agrees with the server's actual era-gating.
  const m = String(version).trim().match(/^(\d+)(?:\.(\d+))?/);
  if (!m) return true;
  const major = parseInt(m[1], 10);
  const minor = parseInt(m[2] || '0', 10);
  // New scheme '26.1', '26.2', '27.x' — a bare major ('26') and snapshots
  // ('26w14a') land here too, as do '1.26'-style names that never shipped.
  const modern = major >= 26 || (major === 1 && minor >= 26);
  return !modern;
}

async function submitVersionChange(e) {
  e.preventDefault();
  
  const newVersion = document.getElementById('vc-new-version').value;

  if (!newVersion) {
    showNotification('Please select a version', 'error');
    return;
  }
  
  const submitBtn = document.getElementById('vc-submit-btn');
  submitBtn.disabled = true;
  submitBtn.textContent = 'Changing Version...';
  
  try {
    // Call API to change version
    const result = await apiRequest(`/api/servers/${currentServerId}/change-version`, {
      method: 'POST',
      body: JSON.stringify({
        version: newVersion
      })
    });

    if (result.success) {
      showNotification(`Version changed successfully from ${result.oldVersion} to ${result.newVersion}`, 'success');
      // Surface the one-way conversion / downgrade warning returned by the server.
      if (result.warning) {
        showNotification(result.warning, 'warning');
      }
      closeVersionChangeModal();
      
      // Refresh server info to show new version
      if (editingServerId) {
        openEditServerModal();
      }
      
      // Reload server list
      loadServers();
    }
  } catch (error) {
    console.error('Failed to change version:', error);
    showNotification(error.message || 'Failed to change version', 'error');
    submitBtn.disabled = false;
    submitBtn.textContent = 'Change Version';
  }
}

// ==================== End Version Change Modal ====================


// Save server (manual configuration / edit mode)
async function saveServer(e) {
  e.preventDefault();
  
  const category = document.getElementById('input-category').value;
  const minRam = document.getElementById('input-min-ram').value;
  const maxRam = document.getElementById('input-max-ram').value;
  const extraJvmArgs = document.getElementById('input-jvm-args').value.trim();
  const javaArgs = `-Xms${minRam} -Xmx${maxRam}${extraJvmArgs ? ' ' + extraJvmArgs : ''}`;
  
  const isBedrock = category === 'bedrock';
  const executable = isBedrock ? 'server.sh' : 'server.jar';

  const serverData = {
    name: document.getElementById('input-name').value,
    serverPath: document.getElementById('input-path').value,
    executable: executable,
    javaArgs: isBedrock ? '' : javaArgs,
    category: category,
    autoStart: document.getElementById('input-auto-start').checked
  };
  
  try {
    if (editingServerId) {
      // Update existing server
      const editResult = await apiRequest(`/api/servers/${editingServerId}`, {
        method: 'PUT',
        body: JSON.stringify(serverData)
      });
      if (editResult.pending) { closeServerModal(); return; }
    } else {
      // Create new server (manual)
      const result = await apiRequest('/api/servers', {
        method: 'POST',
        body: JSON.stringify(serverData)
      });
      
      if (result.pendingApproval) {
        showNotification('Server created and pending admin approval', 'info');
      }
      
      // Select the new server if approved
      await loadServers();
      if (!result.pendingApproval && result.serverId) {
        selectServer(result.serverId);
      }
    }
    
    closeServerModal();
    await loadServers();
    
    if (currentServerId) {
      await loadServerDetails();
    }
  } catch (error) {
    console.error('Failed to save server:', error);
  }
}

// Note: formatBytes is in utils.js

function deleteServer() {
  if (!currentServerId) return;
  
  const server = servers.find(s => s.id === currentServerId);
  showDeleteServerModal(server);
}

function showDeleteServerModal(server) {
  // Remove existing modal if any
  const existing = document.getElementById('delete-server-modal');
  if (existing) existing.remove();
  
  const modal = document.createElement('div');
  modal.id = 'delete-server-modal';
  modal.className = 'modal active';
  modal.innerHTML = `
    <div class="modal-content modal-medium">
      <div class="modal-header">
        <h2>🗑️ Delete Server</h2>
        <button class="close-btn" onclick="closeDeleteServerModal()">&times;</button>
      </div>
      <div class="delete-server-content">
        <p>What would you like to do with <strong>"${escapeHtml(server?.name || 'this server')}"</strong>?</p>
        
        <div class="delete-options">
          <button class="delete-option-btn" onclick="confirmDeleteServer(false)">
            <span class="delete-option-icon">📤</span>
            <div class="delete-option-info">
              <span class="delete-option-title">Remove from Management</span>
              <span class="delete-option-desc">Remove server from console only. Server files will be kept and can be re-imported later.</span>
            </div>
          </button>
          
          <button class="delete-option-btn delete-option-danger" onclick="confirmDeleteServer(true)">
            <span class="delete-option-icon">⚠️</span>
            <div class="delete-option-info">
              <span class="delete-option-title">Delete Everything</span>
              <span class="delete-option-desc">Permanently delete the server and ALL its files including worlds, plugins, and configurations.</span>
            </div>
          </button>
        </div>
        
        <p class="delete-warning">⚠️ Deleting everything cannot be undone!</p>
      </div>
      <div class="modal-footer">
        <button class="btn" onclick="closeDeleteServerModal()">Cancel</button>
      </div>
    </div>
  `;
  
  document.body.appendChild(modal);
  
  // Close on background click
  modal.onclick = (e) => {
    if (e.target.id === 'delete-server-modal') closeDeleteServerModal();
  };
}

function closeDeleteServerModal() {
  const modal = document.getElementById('delete-server-modal');
  if (modal) modal.remove();
}

async function confirmDeleteServer(deleteFiles) {
  if (!currentServerId) return;
  
  const server = servers.find(s => s.id === currentServerId);
  
  // Extra confirmation for full delete
  if (deleteFiles) {
    if (!await confirmAction(`You are about to PERMANENTLY DELETE "${server?.name}" and ALL its files!\n\nThis includes:\n• World data\n• Plugins\n• Configurations\n• Backups in server folder\n\nThis action CANNOT be undone!`, { title: 'FINAL WARNING', icon: '🗑️', okText: 'Delete Everything' })) {
      return;
    }
  }
  
  try {
    const url = deleteFiles 
      ? `/api/servers/${currentServerId}?deleteFiles=true`
      : `/api/servers/${currentServerId}`;
    
    const result = await apiRequest(url, { method: 'DELETE' });

    closeDeleteServerModal();

    if (result.pending) {
      // Pending approval — don't navigate away
      return;
    }

    showNotification(
      deleteFiles
        ? 'Deletion started — see Tasks for progress'
        : 'Removing from management — see Tasks for progress',
      'info'
    );

    currentServerId = null;
    document.getElementById('no-server-view').style.display = 'flex';
    document.getElementById('server-view').style.display = 'none';

    await loadServers();
  } catch (error) {
    console.error('Failed to delete server:', error);
    showNotification('Failed to delete server: ' + error.message, 'error');
  }
}

// ==================== Terminal Functions ====================

// Minimal latency terminal output with smart batching
let terminalBuffer = '';
let terminalUpdateTimer = null;

function appendTerminalOutput(text) {
  terminalBuffer += text;
  
  // Clear any pending update
  if (terminalUpdateTimer) {
    clearTimeout(terminalUpdateTimer);
  }
  
  // Use very short timeout (1ms) to batch rapid updates while maintaining responsiveness
  // This is much faster than requestAnimationFrame (16ms) but still prevents DOM thrashing
  terminalUpdateTimer = setTimeout(() => {
    const terminal = document.getElementById('terminal-output');
    terminal.textContent += terminalBuffer;
    terminal.scrollTop = terminal.scrollHeight;
    terminalBuffer = '';
    terminalUpdateTimer = null;
  }, 1);
}

function clearTerminal() {
  const terminal = document.getElementById('terminal-output');
  terminal.textContent = '';
  terminalBuffer = '';
  if (terminalUpdateTimer) {
    clearTimeout(terminalUpdateTimer);
    terminalUpdateTimer = null;
  }
}

// ==================== Logs Functions ====================

async function loadLogs() {
  if (!currentServerId) return;
  
  try {
    const data = await apiRequest(`/api/servers/${currentServerId}/logs`);
    const logsOutput = document.getElementById('logs-output');
    logsOutput.textContent = data.content || 'No logs available';
    logsOutput.scrollTop = logsOutput.scrollHeight;
  } catch (error) {
    console.error('Failed to load logs:', error);
    const logsOutput = document.getElementById('logs-output');
    logsOutput.textContent = 'Failed to load logs: ' + error.message;
  }
}

function clearLogsView() {
  const logsOutput = document.getElementById('logs-output');
  logsOutput.textContent = '';
}

function sendCommand(command) {
  if (!currentServerId || !socket || !socket.connected) return;
  
  socket.emit('command', { serverId: currentServerId, command });
  appendTerminalOutput(`> ${command}\n`);
}

// ==================== File Explorer ====================

// ==================== File pagination state ====================
let _allFiles = [];
let _filePage = 1;

async function loadFiles(path = '') {
  if (!currentServerId) return;
  
  currentPath = path;
  _filePage = 1;
  
  const fileList = document.getElementById('file-list');
  showTableSkeleton('file-list', 4, 6);
  
  try {
    const data = await apiRequest(`/api/servers/${currentServerId}/files?path=${encodeURIComponent(path)}`);
    
    if (data.isFile) {
      await openFileEditor(path);
      return;
    }
    
    document.getElementById('current-path').textContent = '/' + path;
    
    // Build entries: parent dir + sorted files
    _allFiles = [];
    if (path) {
      const parentPath = path.split('/').slice(0, -1).join('/');
      _allFiles.push({ _raw: { name: '..', isDirectory: true }, _path: parentPath });
    }
    
    const sortedFiles = data.files.sort((a, b) => {
      if (a.isDirectory && !b.isDirectory) return -1;
      if (!a.isDirectory && b.isDirectory) return 1;
      return a.name.localeCompare(b.name);
    });
    
    sortedFiles.forEach(file => {
      const filePath = path ? `${path}/${file.name}` : file.name;
      _allFiles.push({ _raw: file, _path: filePath });
    });
    
    renderFilePage();
  } catch (error) {
    fileList.innerHTML = '<tr><td colspan="4" class="empty-message error">Failed to load files</td></tr>';
    document.getElementById('file-pagination').innerHTML = '';
    console.error('Failed to load files:', error);
  }
}

function renderFilePage() {
  const fileList = document.getElementById('file-list');
  fileList.innerHTML = '';
  
  const start = (_filePage - 1) * PAGE_SIZE;
  const pageItems = _allFiles.slice(start, start + PAGE_SIZE);
  
  pageItems.forEach(item => {
    fileList.appendChild(createFileRow(item._raw, item._path));
  });
  
  renderPagination('file-pagination', _allFiles.length, _filePage, setFilePage);
}

function setFilePage(page) {
  _filePage = page;
  renderFilePage();
}

function createFileRow(file, filePath) {
  const row = document.createElement('tr');
  
  const nameCell = document.createElement('td');
  const nameDiv = document.createElement('div');
  nameDiv.className = 'file-name';
  nameDiv.innerHTML = `
    <span class="file-icon">${file.isDirectory ? '📁' : '📄'}</span>
    <span>${escapeHtml(file.name)}</span>
  `;
  nameDiv.onclick = () => {
    if (file.isDirectory) {
      loadFiles(filePath);
    } else {
      openFileEditor(filePath);
    }
  };
  nameCell.appendChild(nameDiv);
  
  const sizeCell = document.createElement('td');
  sizeCell.textContent = file.isDirectory ? '-' : formatBytes(file.size);
  
  const modifiedCell = document.createElement('td');
  modifiedCell.textContent = file.modified ? new Date(file.modified).toLocaleString() : '-';
  
  const actionsCell = document.createElement('td');
  const actionsDiv = document.createElement('div');
  actionsDiv.className = 'file-actions-cell';
  
  if (file.name !== '..') {
    if (!file.isDirectory) {
      const downloadBtn = document.createElement('button');
      downloadBtn.textContent = 'Download';
      downloadBtn.className = 'btn btn-small action-btn';
      downloadBtn.onclick = (e) => {
        e.stopPropagation();
        downloadFile(filePath);
      };
      actionsDiv.appendChild(downloadBtn);
    } else {
      const zipBtn = document.createElement('button');
      zipBtn.textContent = 'ZIP';
      zipBtn.className = 'btn btn-small action-btn';
      zipBtn.title = 'Download folder as ZIP';
      zipBtn.onclick = (e) => {
        e.stopPropagation();
        downloadFolderAsZip(filePath);
      };
      actionsDiv.appendChild(zipBtn);
    }
    
    const deleteBtn = document.createElement('button');
    deleteBtn.textContent = 'Delete';
    deleteBtn.className = 'btn btn-danger btn-small action-btn';
    deleteBtn.onclick = (e) => {
      e.stopPropagation();
      deleteFile(filePath);
    };
    actionsDiv.appendChild(deleteBtn);
  }
  
  actionsCell.appendChild(actionsDiv);
  
  row.appendChild(nameCell);
  row.appendChild(sizeCell);
  row.appendChild(modifiedCell);
  row.appendChild(actionsCell);
  
  return row;
}

async function openFileEditor(filePath) {
  if (!currentServerId) return;
  
  // Check if this is an NBT file
  if (isNbtFile(filePath)) {
    await openNbtEditor(filePath);
    return;
  }
  
  const requestId = ++fileEditorRequestId;
  currentEditingFile = filePath;

  try {
    const data = await apiRequest(`/api/servers/${currentServerId}/files/read?path=${encodeURIComponent(filePath)}`);

    // A newer openFileEditor()/closeFileEditor() call superseded this one
    // while the request was in flight — discard the stale response so it
    // can't overwrite the editor with the wrong file's content.
    if (requestId !== fileEditorRequestId) return;

    document.getElementById('editor-title').textContent = `Edit: ${filePath}`;
    document.getElementById('file-content').value = data.content;
    document.getElementById('file-editor-modal').classList.add('active');
  } catch (error) {
    console.error('Failed to open file:', error);
  }
}

async function saveFile() {
  if (!currentServerId || !currentEditingFile) return;
  
  try {
    const content = document.getElementById('file-content').value;
    await apiRequest(`/api/servers/${currentServerId}/files/write`, {
      method: 'POST',
      body: JSON.stringify({ path: currentEditingFile, content })
    });
    
    closeFileEditor();
    showNotification('File saved successfully', 'success');
  } catch (error) {
    console.error('Failed to save file:', error);
  }
}

function closeFileEditor() {
  document.getElementById('file-editor-modal').classList.remove('active');
  currentEditingFile = '';
  fileEditorRequestId++; // invalidate any in-flight openFileEditor() request
}

// ==================== NBT Editor ====================

let currentNbtFile = '';
let currentNbtData = null;
let currentNbtCompression = 'gzip';
let currentNbtEditPath = [];
let currentNbtAddParentPath = [];

const NBT_TYPE_NAMES = {
  0: 'End', 1: 'Byte', 2: 'Short', 3: 'Int', 4: 'Long',
  5: 'Float', 6: 'Double', 7: 'ByteArray', 8: 'String',
  9: 'List', 10: 'Compound', 11: 'IntArray', 12: 'LongArray'
};

const NBT_TYPE_ICONS = {
  1: '🔢', 2: '🔢', 3: '🔢', 4: '🔢', 5: '🔢', 6: '🔢',
  7: '📊', 8: '📝', 9: '📋', 10: '📦', 11: '📊', 12: '📊'
};

function isNbtFile(filename) {
  const ext = filename.toLowerCase().split('.').pop();
  return ['dat', 'dat_old', 'dat_mcr', 'nbt', 'schematic'].includes(ext);
}

async function openNbtEditor(filePath) {
  if (!currentServerId) return;
  
  try {
    currentNbtFile = filePath;
    const response = await apiRequest(`/api/servers/${currentServerId}/nbt/read?path=${encodeURIComponent(filePath)}`);
    
    if (response.success) {
      currentNbtData = response.data;
      currentNbtCompression = response.compression || 'gzip';
      
      document.getElementById('nbt-editor-title').textContent = `NBT Editor: ${filePath}`;
      document.getElementById('nbt-compression-info').textContent = `Compression: ${currentNbtCompression || 'none'}`;
      
      renderNbtTree();
      document.getElementById('nbt-editor-modal').classList.add('active');
    }
  } catch (error) {
    console.error('Failed to open NBT file:', error);
    showNotification('Failed to open NBT file: ' + error.message, 'error');
  }
}

function renderNbtTree() {
  const container = document.getElementById('nbt-tree');
  container.innerHTML = '';
  
  if (currentNbtData) {
    container.appendChild(createNbtNode(currentNbtData, []));
  }
}

function getExpandedPaths() {
  const expanded = new Set();
  document.querySelectorAll('#nbt-tree .nbt-node').forEach(node => {
    const children = node.querySelector(':scope > .nbt-children');
    if (children && !children.classList.contains('collapsed')) {
      expanded.add(node.dataset.nbtPath);
    }
  });
  return expanded;
}

function restoreExpandedPaths(expanded) {
  document.querySelectorAll('#nbt-tree .nbt-node').forEach(node => {
    if (expanded.has(node.dataset.nbtPath)) {
      const children = node.querySelector(':scope > .nbt-children');
      const toggle = node.querySelector(':scope > .nbt-node-header > .nbt-toggle');
      if (children) {
        children.classList.remove('collapsed');
        if (toggle) {
          toggle.textContent = '▼';
          toggle.classList.add('expanded');
        }
      }
    }
  });
}

function createNbtNode(tag, path) {
  const node = document.createElement('div');
  node.className = 'nbt-node';
  node.dataset.nbtPath = path.join('.');
  
  const header = document.createElement('div');
  header.className = 'nbt-node-header';
  
  const isExpandable = tag.type === 10 || tag.type === 9; // Compound or List
  
  if (isExpandable) {
    const toggle = document.createElement('span');
    toggle.className = 'nbt-toggle';
    toggle.textContent = '▶';
    toggle.onclick = (e) => {
      e.stopPropagation();
      const children = node.querySelector('.nbt-children');
      if (children) {
        children.classList.toggle('collapsed');
        toggle.textContent = children.classList.contains('collapsed') ? '▶' : '▼';
        toggle.classList.toggle('expanded', !children.classList.contains('collapsed'));
      }
    };
    header.appendChild(toggle);
  } else {
    const spacer = document.createElement('span');
    spacer.className = 'nbt-toggle-spacer';
    header.appendChild(spacer);
  }
  
  const icon = document.createElement('span');
  icon.className = 'nbt-icon';
  icon.textContent = NBT_TYPE_ICONS[tag.type] || '❓';
  header.appendChild(icon);
  
  const name = document.createElement('span');
  name.className = 'nbt-name';
  name.textContent = tag.name || '(unnamed)';
  header.appendChild(name);
  
  const type = document.createElement('span');
  type.className = 'nbt-type';
  type.textContent = `[${NBT_TYPE_NAMES[tag.type] || 'Unknown'}]`;
  header.appendChild(type);
  
  // Show value preview for simple types
  if (!isExpandable && tag.type !== 7 && tag.type !== 11 && tag.type !== 12) {
    const value = document.createElement('span');
    value.className = 'nbt-value';
    value.textContent = `: ${formatNbtValue(tag.value, tag.type)}`;
    header.appendChild(value);
    
    // Make editable
    header.classList.add('nbt-editable');
    header.onclick = () => openNbtValueEditor(tag, path);
  } else if (tag.type === 7 || tag.type === 11 || tag.type === 12) {
    // Array types - show count
    const value = document.createElement('span');
    value.className = 'nbt-value nbt-array-info';
    const arrLen = Array.isArray(tag.value) ? tag.value.length : 0;
    value.textContent = `: [${arrLen} entries]`;
    header.appendChild(value);
  }
  
  // Action buttons
  const actions = document.createElement('div');
  actions.className = 'nbt-actions';
  
  if (isExpandable) {
    const addBtn = document.createElement('button');
    addBtn.className = 'btn btn-small nbt-action-btn';
    addBtn.textContent = '+';
    addBtn.title = 'Add child tag';
    addBtn.onclick = (e) => {
      e.stopPropagation();
      openNbtAddModal(path);
    };
    actions.appendChild(addBtn);
  }
  
  if (path.length > 0) {
    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'btn btn-danger btn-small nbt-action-btn';
    deleteBtn.textContent = '×';
    deleteBtn.title = 'Delete tag';
    deleteBtn.onclick = (e) => {
      e.stopPropagation();
      deleteNbtTag(path);
    };
    actions.appendChild(deleteBtn);
  }
  
  header.appendChild(actions);
  node.appendChild(header);
  
  // Render children for compound and list
  if (tag.type === 10 && Array.isArray(tag.value)) {
    const children = document.createElement('div');
    children.className = 'nbt-children collapsed';
    tag.value.forEach((child, index) => {
      children.appendChild(createNbtNode(child, [...path, child.name]));
    });
    node.appendChild(children);
  } else if (tag.type === 9 && tag.value && tag.value.items) {
    const children = document.createElement('div');
    children.className = 'nbt-children collapsed';
    tag.value.items.forEach((item, index) => {
      const listItem = {
        type: item.type,
        name: `[${index}]`,
        value: item.value
      };
      children.appendChild(createNbtNode(listItem, [...path, index.toString()]));
    });
    node.appendChild(children);
  }
  
  return node;
}

function formatNbtValue(value, type) {
  if (type === 8) return `"${value}"`;
  if (type === 5 || type === 6) return value.toFixed(4);
  return String(value);
}

function openNbtValueEditor(tag, path) {
  currentNbtEditPath = path;
  
  document.getElementById('nbt-value-label').textContent = tag.name || 'Value';
  document.getElementById('nbt-value-type').textContent = `Type: ${NBT_TYPE_NAMES[tag.type]}`;
  document.getElementById('nbt-value-input').value = tag.value;
  document.getElementById('nbt-value-input').dataset.type = tag.type;
  
  document.getElementById('nbt-value-modal').classList.add('active');
}

function closeNbtValueModal() {
  document.getElementById('nbt-value-modal').classList.remove('active');
  currentNbtEditPath = [];
}

function saveNbtValue() {
  const input = document.getElementById('nbt-value-input');
  let value = input.value;
  const type = parseInt(input.dataset.type);
  
  // Convert value based on type
  switch (type) {
    case 1: value = parseInt(value); break; // Byte
    case 2: value = parseInt(value); break; // Short
    case 3: value = parseInt(value); break; // Int
    case 4: value = parseInt(value); break; // Long (may lose precision)
    case 5: value = parseFloat(value); break; // Float
    case 6: value = parseFloat(value); break; // Double
    case 8: value = String(value); break; // String
  }
  
  // Update the value in the data structure
  updateNbtDataValue(currentNbtData, currentNbtEditPath, value);
  
  // Re-render preserving expanded state, and close modal
  const expandedPaths = getExpandedPaths();
  renderNbtTree();
  restoreExpandedPaths(expandedPaths);
  closeNbtValueModal();
  showNotification('Value updated (save to apply)', 'info');
}

function updateNbtDataValue(data, path, newValue) {
  if (path.length === 0) return;
  
  let current = data;
  for (let i = 0; i < path.length - 1; i++) {
    const key = path[i];
    if (current.type === 10) { // Compound
      current = current.value.find(c => c.name === key);
    } else if (current.type === 9) { // List
      current = current.value.items[parseInt(key)];
    }
  }
  
  const finalKey = path[path.length - 1];
  if (current.type === 10) {
    const target = current.value.find(c => c.name === finalKey);
    if (target) target.value = newValue;
  } else if (current.type === 9) {
    current.value.items[parseInt(finalKey)].value = newValue;
  } else {
    current.value = newValue;
  }
}

function openNbtAddModal(parentPath) {
  currentNbtAddParentPath = parentPath;
  document.getElementById('nbt-add-name').value = '';
  document.getElementById('nbt-add-value').value = '';
  document.getElementById('nbt-add-type').value = '8'; // Default to String
  updateNbtAddValue();
  document.getElementById('nbt-add-modal').classList.add('active');
}

function closeNbtAddModal() {
  document.getElementById('nbt-add-modal').classList.remove('active');
  currentNbtAddParentPath = [];
}

function updateNbtAddValue() {
  const type = parseInt(document.getElementById('nbt-add-type').value);
  const valueGroup = document.getElementById('nbt-add-value-group');
  
  // Hide value input for compound type
  valueGroup.style.display = type === 10 ? 'none' : 'block';
}

function confirmAddNbtTag() {
  const name = document.getElementById('nbt-add-name').value.trim();
  const type = parseInt(document.getElementById('nbt-add-type').value);
  let value = document.getElementById('nbt-add-value').value;
  
  if (!name) {
    showNotification('Please enter a tag name', 'warning');
    return;
  }
  
  // Create the new tag
  let newTag = { type, name };
  
  switch (type) {
    case 1: case 2: case 3: case 4: newTag.value = parseInt(value) || 0; break;
    case 5: case 6: newTag.value = parseFloat(value) || 0.0; break;
    case 8: newTag.value = value || ''; break;
    case 10: newTag.value = []; break; // Empty compound
  }
  
  // Find parent and add tag
  addNbtTagToData(currentNbtData, currentNbtAddParentPath, newTag);
  
  const expandedAfterAdd = getExpandedPaths();
  renderNbtTree();
  restoreExpandedPaths(expandedAfterAdd);
  closeNbtAddModal();
  showNotification('Tag added (save to apply)', 'info');
}

function addNbtTagToData(data, parentPath, newTag) {
  let current = data;
  
  for (const key of parentPath) {
    if (current.type === 10) {
      current = current.value.find(c => c.name === key);
    } else if (current.type === 9) {
      current = current.value.items[parseInt(key)];
    }
  }
  
  if (current.type === 10) {
    current.value.push(newTag);
  } else if (current.type === 9) {
    current.value.items.push({ type: newTag.type, value: newTag.value });
  }
}

async function deleteNbtTag(path) {
  if (!await confirmAction('Are you sure you want to delete this tag?', { title: 'Delete NBT Tag', icon: '🗑️', okText: 'Delete' })) return;
  
  deleteNbtTagFromData(currentNbtData, path);
  const expandedAfterDelete = getExpandedPaths();
  renderNbtTree();
  restoreExpandedPaths(expandedAfterDelete);
  showNotification('Tag deleted (save to apply)', 'info');
}

function deleteNbtTagFromData(data, path) {
  if (path.length === 0) return;
  
  let current = data;
  for (let i = 0; i < path.length - 1; i++) {
    const key = path[i];
    if (current.type === 10) {
      current = current.value.find(c => c.name === key);
    } else if (current.type === 9) {
      current = current.value.items[parseInt(key)];
    }
  }
  
  const finalKey = path[path.length - 1];
  if (current.type === 10) {
    current.value = current.value.filter(c => c.name !== finalKey);
  } else if (current.type === 9) {
    current.value.items.splice(parseInt(finalKey), 1);
  }
}

async function saveNbtFile() {
  if (!currentServerId || !currentNbtFile || !currentNbtData) return;
  
  try {
    await apiRequest(`/api/servers/${currentServerId}/nbt/write`, {
      method: 'POST',
      body: JSON.stringify({
        path: currentNbtFile,
        data: currentNbtData,
        compression: currentNbtCompression
      })
    });
    
    showNotification('NBT file saved successfully', 'success');
  } catch (error) {
    console.error('Failed to save NBT file:', error);
    showNotification('Failed to save NBT file: ' + error.message, 'error');
  }
}

function closeNbtEditor() {
  document.getElementById('nbt-editor-modal').classList.remove('active');
  currentNbtFile = '';
  currentNbtData = null;
}

function expandAllNbt() {
  document.querySelectorAll('.nbt-children').forEach(el => {
    el.classList.remove('collapsed');
  });
  document.querySelectorAll('.nbt-toggle').forEach(el => {
    el.textContent = '▼';
    el.classList.add('expanded');
  });
}

function collapseAllNbt() {
  document.querySelectorAll('.nbt-children').forEach(el => {
    el.classList.add('collapsed');
  });
  document.querySelectorAll('.nbt-toggle').forEach(el => {
    el.textContent = '▶';
    el.classList.remove('expanded');
  });
}

function addNbtTag() {
  openNbtAddModal([]);
}

async function createNewFile() {
  if (!currentServerId) return;
  
  const name = prompt('Enter file name:');
  if (!name) return;
  
  try {
    const filePath = currentPath ? `${currentPath}/${name}` : name;
    await apiRequest(`/api/servers/${currentServerId}/files/create`, {
      method: 'POST',
      body: JSON.stringify({ path: filePath, type: 'file' })
    });
    
    loadFiles(currentPath);
  } catch (error) {
    console.error('Failed to create file:', error);
  }
}

async function createNewFolder() {
  if (!currentServerId) return;
  
  const name = prompt('Enter folder name:');
  if (!name) return;
  
  try {
    const filePath = currentPath ? `${currentPath}/${name}` : name;
    await apiRequest(`/api/servers/${currentServerId}/files/create`, {
      method: 'POST',
      body: JSON.stringify({ path: filePath, type: 'directory' })
    });
    
    loadFiles(currentPath);
  } catch (error) {
    console.error('Failed to create folder:', error);
  }
}

async function deleteFile(filePath) {
  if (!currentServerId) return;
  if (!await confirmAction(`Are you sure you want to delete ${filePath}?`, { title: 'Delete File', icon: '🗑️', okText: 'Delete' })) return;
  
  try {
    await apiRequest(`/api/servers/${currentServerId}/files/delete`, {
      method: 'DELETE',
      body: JSON.stringify({ path: filePath })
    });
    
    loadFiles(currentPath);
  } catch (error) {
    console.error('Failed to delete file:', error);
  }
}

function downloadFile(filePath) {
  if (!currentServerId) return;
  window.location.href = `/api/servers/${currentServerId}/files/download?path=${encodeURIComponent(filePath)}`;
}

async function downloadFolderAsZip(folderPath) {
  if (!currentServerId) return;
  // The zip is built in the background; the Tasks panel shows progress and, when
  // ready, a Download button (GET /api/jobs/<id>/download).
  try {
    await apiRequest(`/api/servers/${currentServerId}/files/zip`, {
      method: 'POST',
      body: JSON.stringify({ path: folderPath })
    });
    showNotification('Preparing ZIP — see Tasks for progress and download', 'info');
    openJobsPanel();
  } catch (error) {
    showNotification('Failed to start ZIP: ' + error.message, 'error');
  }
}

async function uploadFile(file) {
  if (!currentServerId) return;
  
  const formData = new FormData();
  formData.append('file', file);
  formData.append('path', currentPath);
  
  try {
    const response = await fetch(`/api/servers/${currentServerId}/files/upload`, {
      method: 'POST',
      headers: window.csrfToken ? { 'X-CSRF-Token': window.csrfToken } : {},
      body: formData
    });
    
    const result = await response.json();
    if (result.success) {
      showNotification('File uploaded successfully', 'success');
      loadFiles(currentPath);
    } else {
      throw new Error(result.error || 'Upload failed');
    }
  } catch (error) {
    console.error('Failed to upload file:', error);
    showNotification('Upload failed: ' + error.message, 'error');
  }
}

// ==================== Backup Functions ====================

async function loadBackups() {
  if (!currentServerId) return;
  
  // Load schedule status
  loadBackupSchedule();
  
  showTableSkeleton('backup-list', 4, 4);
  
  try {
    const data = await apiRequest(`/api/servers/${currentServerId}/backups`);
    const backupList = document.getElementById('backup-list');
    backupList.innerHTML = '';
    
    if (data.backups.length === 0) {
      backupList.innerHTML = '<tr><td colspan="4" class="empty-state"><h3>No backups yet</h3><p>Create your first backup to protect your server</p></td></tr>';
      return;
    }
    
    data.backups.forEach(backup => {
      const row = document.createElement('tr');
      let prefix = '';
      if (backup.isScheduled) prefix = '📅 ';
      const expiredBadge = backup.expired
        ? '<span class="badge badge-warning" title="This backup exceeds the retention limit">⚠️ Expired</span> '
        : '';
      const checksumBadge = backup.hasChecksum
        ? '<span class="badge badge-success" title="Checksum present">✓</span>'
        : '';
      row.innerHTML = `
        <td>${prefix}${escapeHtml(backup.name)} ${expiredBadge}${checksumBadge}</td>
        <td>${formatBytes(backup.size)}</td>
        <td>${new Date(backup.created).toLocaleString()}</td>
        <td>
          <div class="file-actions-cell">
            <button class="btn btn-small action-btn" onclick="downloadBackup('${escapeHtml(backup.name)}')">Download</button>
            <button class="btn btn-success btn-small action-btn" onclick="restoreBackup('${escapeHtml(backup.name)}')">Restore</button>
            <button class="btn btn-small action-btn" onclick="verifyBackup('${escapeHtml(backup.name)}')">Verify</button>
            <button class="btn btn-small action-btn" onclick="openRenameBackupModal('${escapeHtml(backup.name)}')">Rename</button>
            <button class="btn btn-danger btn-small action-btn" onclick="deleteBackup('${escapeHtml(backup.name)}')">Delete</button>
          </div>
        </td>
      `;
      backupList.appendChild(row);
    });
  } catch (error) {
    console.error('Failed to load backups:', error);
  }
}

function openCreateBackupModal() {
  if (!currentServerId) return;
  document.getElementById('backup-custom-name').value = '';
  document.getElementById('backup-compression-level').value = 6;
  document.getElementById('backup-compression-level-val').textContent = '6';
  document.getElementById('create-backup-modal').classList.add('active');
}

function closeCreateBackupModal() {
  document.getElementById('create-backup-modal').classList.remove('active');
}

async function createBackup() {
  if (!currentServerId) return;

  const compressionLevel = parseInt(document.getElementById('backup-compression-level').value) || 6;
  const customName = document.getElementById('backup-custom-name').value.trim();

  closeCreateBackupModal();
  showNotification('⏳ Backup started. The server will be stopped if running, backed up, then restarted.', 'info');

  try {
    const payload = { compressionLevel, backupType: 'manual' };
    if (customName) payload.customName = customName;
    const result = await apiRequest(`/api/servers/${currentServerId}/backups/create`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    if (result.pending) return;
    openJobsPanel();
  } catch (error) {
    console.error('Failed to start backup:', error);
    showNotification('Failed to start backup: ' + error.message, 'error');
  }
}

function downloadBackup(name) {
  if (!currentServerId) return;
  window.location.href = `/api/servers/${currentServerId}/backups/download?name=${encodeURIComponent(name)}`;
}

let _restoreTargetName = null;

function restoreBackup(name) {
  if (!currentServerId) return;
  _restoreTargetName = name;
  document.getElementById('restore-backup-name').textContent = name;
  document.getElementById('restore-confirm-modal').classList.add('active');
}

function closeRestoreModal() {
  document.getElementById('restore-confirm-modal').classList.remove('active');
  _restoreTargetName = null;
}

async function confirmRestore() {
  if (!currentServerId || !_restoreTargetName) return;
  const name = _restoreTargetName;
  closeRestoreModal();
  showNotification('🔄 Restore started. The server will be stopped, files replaced, then restarted.', 'info');
  try {
    await apiRequest(`/api/servers/${currentServerId}/backups/restore`, {
      method: 'POST',
      body: JSON.stringify({ name })
    });
    openJobsPanel();
  } catch (error) {
    console.error('Failed to start restore:', error);
    showNotification('Failed to start restore', 'error');
  }
}

let _renameBackupOldName = null;

function openRenameBackupModal(name) {
  if (!currentServerId) return;
  _renameBackupOldName = name;
  document.getElementById('rename-backup-current').textContent = name;
  const base = name.replace(/\.zip$/i, '');
  document.getElementById('rename-backup-new-name').value = base;
  document.getElementById('rename-backup-modal').classList.add('active');
}

function closeRenameBackupModal() {
  document.getElementById('rename-backup-modal').classList.remove('active');
  _renameBackupOldName = null;
}

async function confirmRenameBackup() {
  if (!currentServerId || !_renameBackupOldName) return;
  const newName = document.getElementById('rename-backup-new-name').value.trim();
  if (!newName) {
    showNotification('Please enter a new name', 'error');
    return;
  }
  const oldName = _renameBackupOldName;
  closeRenameBackupModal();
  try {
    await apiRequest(`/api/servers/${currentServerId}/backups/rename`, {
      method: 'POST',
      body: JSON.stringify({ oldName, newName })
    });
    showNotification('Backup renamed successfully', 'success');
    loadBackups();
  } catch (error) {
    console.error('Failed to rename backup:', error);
    showNotification('Failed to rename backup', 'error');
  }
}

function triggerImportBackup() {
  if (!currentServerId) return;
  document.getElementById('import-backup-input').click();
}

async function importBackup(input) {
  if (!currentServerId || !input.files || !input.files[0]) return;
  const file = input.files[0];
  input.value = '';
  await importBackupFile(file);
}

async function importBackupFile(file) {
  if (!currentServerId || !file) return;
  showNotification(`Uploading ${file.name}…`, 'info');
  const formData = new FormData();
  formData.append('file', file);
  try {
    const response = await fetch(`/api/servers/${currentServerId}/backups/import`, {
      method: 'POST',
      headers: window.csrfToken ? { 'X-CSRF-Token': window.csrfToken } : {},
      body: formData
    });
    const result = await response.json();
    if (!response.ok) {
      showNotification(`Import failed: ${result.error}`, 'error');
      return;
    }
    if (result.success) {
      showNotification(`✅ Backup imported: ${result.backup} (${formatBytes(result.size)})`, 'success');
      loadBackups();
    }
  } catch (error) {
    console.error('Failed to import backup:', error);
    showNotification('Failed to import backup', 'error');
  }
}

async function deleteBackup(name) {
  if (!currentServerId) return;
  if (!await confirmAction(`Delete backup "${name}"?`, { title: 'Delete Backup', icon: '🗑️', okText: 'Delete' })) return;
  
  try {
    const result = await apiRequest(`/api/servers/${currentServerId}/backups/delete`, {
      method: 'DELETE',
      body: JSON.stringify({ name })
    });
    if (result.pending) return;
    loadBackups();
  } catch (error) {
    console.error('Failed to delete backup:', error);
  }
}

async function verifyBackup(name) {
  if (!currentServerId) return;
  try {
    showNotification(`Verifying ${name}…`, 'info');
    const result = await apiRequest(`/api/servers/${currentServerId}/backups/verify`, {
      method: 'POST',
      body: JSON.stringify({ name })
    });
    if (result.success) {
      const short = result.checksum ? result.checksum.substring(0, 16) + '…' : 'N/A';
      showNotification(`✅ Backup OK — SHA-256: ${short}`, 'success');
    } else {
      showNotification(`❌ Backup failed verification: ${result.error}`, 'error');
    }
    // Refresh list to show/update checksum badge
    loadBackups();
  } catch (error) {
    console.error('Failed to verify backup:', error);
    showNotification('Backup verification failed', 'error');
  }
}

let backupHistoryLoaded = false;

function toggleBackupHistory() {
  const container = document.getElementById('backup-history-container');
  const icon = document.getElementById('backup-history-toggle-icon');
  if (container.style.display === 'none') {
    container.style.display = '';
    icon.textContent = '▲';
    if (!backupHistoryLoaded) loadBackupHistory();
  } else {
    container.style.display = 'none';
    icon.textContent = '▼';
  }
}

async function loadBackupHistory() {
  if (!currentServerId) return;
  backupHistoryLoaded = true;
  try {
    const data = await apiRequest(`/api/servers/${currentServerId}/backups/history`);
    const tbody = document.getElementById('backup-history-list');
    tbody.innerHTML = '';

    if (!data.events || data.events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-message">No backup history yet</td></tr>';
      return;
    }

    const typeLabels = {
      'manual': '🖐 Manual',
      'scheduled': '📅 Scheduled',
      'pre-version-change': '🔄 Pre-Update',
      'pre-jar-update': '⚙️ Pre-JAR'
    };

    data.events.forEach(evt => {
      const row = document.createElement('tr');
      const time = new Date(evt.timestamp).toLocaleString();
      const typeLabel = typeLabels[evt.type] || escapeHtml(evt.type || '');
      const fileName = evt.backupName
        ? `<span title="${escapeHtml(evt.backupName)}">${escapeHtml(evt.backupName.substring(0, 36))}${evt.backupName.length > 36 ? '…' : ''}</span>`
        : '—';
      const size = evt.size ? formatBytes(evt.size) : '—';
      const status = evt.success
        ? `<span class="badge badge-success">✅ OK</span>`
        : `<span class="badge badge-danger" title="${escapeHtml(evt.error || '')}">❌ Failed</span>`;
      const checksum = evt.checksum
        ? `<span class="badge badge-secondary" title="${escapeHtml(evt.checksum)}">${evt.checksum.substring(0, 8)}…</span>`
        : '—';
      row.innerHTML = `<td>${time}</td><td>${typeLabel}</td><td>${fileName}</td><td>${size}</td><td>${status}</td><td>${checksum}</td>`;
      tbody.appendChild(row);
    });
  } catch (error) {
    console.error('Failed to load backup history:', error);
  }
}


// ==================== Backup Scheduling ====================

async function loadBackupSchedule() {
  if (!currentServerId) return;
  
  try {
    const data = await apiRequest(`/api/servers/${currentServerId}/backups/schedule`);
    const statusBanner = document.getElementById('schedule-status');
    
    if (data.schedule && data.schedule.enabled) {
      const schedule = data.schedule;
      let scheduleText = '';
      
      switch (schedule.type) {
        case 'hourly':
          scheduleText = `Every hour at :${String(schedule.minute).padStart(2, '0')}`;
          break;
        case 'daily':
          scheduleText = `Daily at ${String(schedule.hour).padStart(2, '0')}:${String(schedule.minute).padStart(2, '0')}`;
          break;
        case 'weekly':
          const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
          scheduleText = `Every ${days[schedule.dayOfWeek]} at ${String(schedule.hour).padStart(2, '0')}:${String(schedule.minute).padStart(2, '0')}`;
          break;
        case 'custom':
          scheduleText = `Custom: ${schedule.cron}`;
          break;
      }
      
      document.getElementById('schedule-text').textContent = `Scheduled: ${scheduleText}`;
      
      if (schedule.nextRun) {
        const nextRun = new Date(schedule.nextRun);
        document.getElementById('next-backup-text').textContent = `Next: ${nextRun.toLocaleString()}`;
      } else {
        document.getElementById('next-backup-text').textContent = '';
      }
      
      statusBanner.style.display = 'flex';
    } else {
      statusBanner.style.display = 'none';
    }
  } catch (error) {
    console.error('Failed to load backup schedule:', error);
    document.getElementById('schedule-status').style.display = 'none';
  }
}

function openScheduleModal() {
  const modal = document.getElementById('schedule-modal');
  modal.classList.add('active');

  // Reset to defaults first, then load the saved schedule (if any) over them,
  // so stale values from a previously cancelled edit never resurface.
  resetScheduleForm();
  loadScheduleIntoModal();
}

function closeScheduleModal() {
  document.getElementById('schedule-modal').classList.remove('active');
  resetScheduleForm();
}

function resetScheduleForm() {
  document.getElementById('schedule-type').value = 'daily';
  document.getElementById('schedule-hour').value = 3;
  document.getElementById('schedule-minute').value = 0;
  document.getElementById('schedule-day').value = 0;
  document.getElementById('schedule-cron').value = '';
  document.getElementById('schedule-compression-level').value = 6;
  document.getElementById('schedule-compression-level-val').textContent = 6;
  document.getElementById('schedule-stop-server').checked = true;
  document.getElementById('schedule-restart-after').checked = true;
  updateScheduleOptions();
}

async function loadScheduleIntoModal() {
  if (!currentServerId) return;
  
  try {
    const data = await apiRequest(`/api/servers/${currentServerId}/backups/schedule`);
    
    if (data.schedule) {
      const s = data.schedule;
      document.getElementById('schedule-type').value = s.type || 'daily';
      document.getElementById('schedule-hour').value = s.hour || 3;
      document.getElementById('schedule-minute').value = s.minute || 0;
      document.getElementById('schedule-day').value = s.dayOfWeek || 0;
      document.getElementById('schedule-cron').value = s.cron || '';
      document.getElementById('schedule-stop-server').checked = s.stopServer !== false;
      document.getElementById('schedule-restart-after').checked = s.restartAfter !== false;

      const compLvl = (s.compressionLevel !== undefined) ? s.compressionLevel : 6;
      document.getElementById('schedule-compression-level').value = compLvl;
      document.getElementById('schedule-compression-level-val').textContent = compLvl;
      
      updateScheduleOptions();
    }
  } catch (error) {
    console.error('Failed to load schedule into modal:', error);
  }
}

function updateScheduleOptions() {
  const type = document.getElementById('schedule-type').value;
  const dayGroup = document.getElementById('schedule-day-group');
  const hourGroup = document.getElementById('schedule-hour-group');
  const timeOptions = document.getElementById('schedule-time-options');
  const cronGroup = document.getElementById('schedule-cron-group');
  
  // Reset visibility
  dayGroup.style.display = 'none';
  hourGroup.style.display = 'block';
  timeOptions.style.display = 'block';
  cronGroup.style.display = 'none';
  
  switch (type) {
    case 'hourly':
      hourGroup.style.display = 'none';
      break;
    case 'daily':
      // Default - hour and minute shown
      break;
    case 'weekly':
      dayGroup.style.display = 'block';
      break;
    case 'custom':
      timeOptions.style.display = 'none';
      cronGroup.style.display = 'block';
      break;
  }
}

async function saveSchedule() {
  if (!currentServerId) return;
  
  const type = document.getElementById('schedule-type').value;
  const scheduleData = {
    enabled: true,
    type: type,
    hour: parseInt(document.getElementById('schedule-hour').value) || 3,
    minute: parseInt(document.getElementById('schedule-minute').value) || 0,
    dayOfWeek: parseInt(document.getElementById('schedule-day').value) || 0,
    cron: document.getElementById('schedule-cron').value,
    compressionLevel: parseInt(document.getElementById('schedule-compression-level').value) || 6,
    stopServer: document.getElementById('schedule-stop-server').checked,
    restartAfter: document.getElementById('schedule-restart-after').checked
  };
  
  try {
    const result = await apiRequest(`/api/servers/${currentServerId}/backups/schedule`, {
      method: 'POST',
      body: JSON.stringify(scheduleData)
    });
    
    if (result.success) {
      showNotification('Backup schedule saved successfully!', 'success');
      closeScheduleModal();
      loadBackupSchedule();
    }
  } catch (error) {
    console.error('Failed to save schedule:', error);
    showNotification('Failed to save backup schedule', 'error');
  }
}

async function deleteExpiredBackups() {
  if (!currentServerId) return;
  if (!await confirmAction('Delete all backups beyond the retention limit for this server?', { title: 'Delete Expired Backups', icon: '🗑️', okText: 'Delete Expired', okClass: 'btn-danger' })) return;
  try {
    const result = await apiRequest(`/api/servers/${currentServerId}/backups/delete-expired`, { method: 'POST' });
    if (result.success) {
      showNotification(`Deleted ${result.deleted} expired backup(s)`, 'success');
      loadBackups();
    }
  } catch (error) {
    console.error('Failed to delete expired backups:', error);
    const msg = error?.data?.error || 'Failed to delete expired backups';
    showNotification(msg, 'error');
  }
}

async function deleteSchedule() {
  if (!currentServerId) return;
  if (!await confirmAction('Are you sure you want to disable the backup schedule?', { title: 'Disable Schedule', icon: '📅', okText: 'Disable', okClass: 'btn-primary' })) return;
  
  try {
    await apiRequest(`/api/servers/${currentServerId}/backups/schedule`, {
      method: 'DELETE'
    });
    
    showNotification('Backup schedule disabled', 'info');
    loadBackupSchedule();
  } catch (error) {
    console.error('Failed to delete schedule:', error);
    showNotification('Failed to disable backup schedule', 'error');
  }
}

// ==================== Task Scheduler ====================

let editingTaskId = null;

async function loadTasks() {
  if (!currentServerId) return;
  
  showTableSkeleton('task-list', 8, 3);
  
  try {
    const data = await apiRequest(`/api/servers/${currentServerId}/tasks`);
    const taskList = document.getElementById('task-list');
    taskList.innerHTML = '';
    
    if (!data.tasks || data.tasks.length === 0) {
      taskList.innerHTML = '<tr><td colspan="8" class="empty-message">No tasks configured. Create one to get started!</td></tr>';
      return;
    }
    
    data.tasks.forEach(task => {
      const row = document.createElement('tr');
      
      const statusCell = document.createElement('td');
      const statusBadge = document.createElement('span');
      statusBadge.className = task.enabled ? 'badge badge-success' : 'badge badge-secondary';
      statusBadge.textContent = task.enabled ? 'Enabled' : 'Disabled';
      statusCell.appendChild(statusBadge);
      
      const nameCell = document.createElement('td');
      nameCell.textContent = task.name;
      
      const actionCell = document.createElement('td');
      const actionBadge = document.createElement('span');
      actionBadge.className = 'badge';
      switch (task.action) {
        case 'START':
          actionBadge.classList.add('badge-success');
          actionBadge.textContent = '▶️ Start';
          break;
        case 'STOP':
          actionBadge.classList.add('badge-danger');
          actionBadge.textContent = '⏹️ Stop';
          break;
        case 'REBOOT':
          actionBadge.classList.add('badge-warning');
          actionBadge.textContent = '🔄 Reboot';
          break;
        case 'COMMAND':
          actionBadge.classList.add('badge-info');
          actionBadge.textContent = '⌨️ Command';
          break;
      }
      actionCell.appendChild(actionBadge);
      
      const intervalCell = document.createElement('td');
      intervalCell.textContent = task.interval;
      intervalCell.style.fontFamily = 'monospace';
      intervalCell.style.fontSize = '12px';
      
      const runsCell = document.createElement('td');
      if (task.runs > 0) {
        runsCell.textContent = `${task.runCount || 0}/${task.runs}`;
      } else {
        runsCell.textContent = task.runCount || 0;
      }
      
      const lastRunCell = document.createElement('td');
      lastRunCell.textContent = task.lastRun ? new Date(task.lastRun).toLocaleString() : 'Never';
      
      const nextRunCell = document.createElement('td');
      nextRunCell.textContent = task.nextRun ? new Date(task.nextRun).toLocaleString() : '-';
      
      const actionsCell = document.createElement('td');
      const editBtn = document.createElement('button');
      editBtn.textContent = 'Edit';
      editBtn.className = 'btn btn-small action-btn';
      editBtn.onclick = () => openEditTaskModal(task);
      
      const deleteBtn = document.createElement('button');
      deleteBtn.textContent = 'Delete';
      deleteBtn.className = 'btn btn-danger btn-small action-btn';
      deleteBtn.onclick = () => deleteTask(task.id);
      
      actionsCell.appendChild(editBtn);
      actionsCell.appendChild(deleteBtn);
      
      row.appendChild(statusCell);
      row.appendChild(nameCell);
      row.appendChild(actionCell);
      row.appendChild(intervalCell);
      row.appendChild(runsCell);
      row.appendChild(lastRunCell);
      row.appendChild(nextRunCell);
      row.appendChild(actionsCell);
      
      taskList.appendChild(row);
    });
  } catch (error) {
    console.error('Failed to load tasks:', error);
    showNotification('Failed to load tasks', 'error');
  }
}

function openCreateTaskModal() {
  editingTaskId = null;
  document.getElementById('task-modal-title').textContent = 'Create Task';
  document.getElementById('task-name').value = '';
  document.getElementById('task-action').value = 'START';
  document.getElementById('task-interval').value = '0 3 * * *';
  document.getElementById('task-command').value = '';
  document.getElementById('task-runs').value = '0';
  document.getElementById('task-enabled').checked = true;
  document.getElementById('task-delete-after').checked = false;
  document.getElementById('task-delete-after-runs').checked = false;
  
  updateTaskActionOptions();
  document.getElementById('task-modal').classList.add('active');
}

function openEditTaskModal(task) {
  editingTaskId = task.id;
  document.getElementById('task-modal-title').textContent = 'Edit Task';
  document.getElementById('task-name').value = task.name;
  document.getElementById('task-action').value = task.action;
  document.getElementById('task-interval').value = task.interval;
  document.getElementById('task-command').value = task.command || '';
  document.getElementById('task-runs').value = task.runs || 0;
  document.getElementById('task-enabled').checked = task.enabled;
  document.getElementById('task-delete-after').checked = task.deleteAfterExecution;
  document.getElementById('task-delete-after-runs').checked = task.deleteAfterRunsCount;
  
  updateTaskActionOptions();
  document.getElementById('task-modal').classList.add('active');
}

function closeTaskModal() {
  document.getElementById('task-modal').classList.remove('active');
  editingTaskId = null;
}

function updateTaskActionOptions() {
  const action = document.getElementById('task-action').value;
  const commandGroup = document.getElementById('task-command-group');
  
  if (action === 'COMMAND') {
    commandGroup.style.display = 'block';
  } else {
    commandGroup.style.display = 'none';
  }
}

function updateTaskRunsRequired() {
  const deleteAfterRuns = document.getElementById('task-delete-after-runs').checked;
  const runsInput = document.getElementById('task-runs');
  
  if (deleteAfterRuns && runsInput.value === '0') {
    runsInput.value = '1';
  }
}

async function saveTask() {
  if (!currentServerId) return;
  
  const name = document.getElementById('task-name').value.trim();
  const action = document.getElementById('task-action').value;
  const interval = document.getElementById('task-interval').value.trim();
  const command = document.getElementById('task-command').value.trim();
  const runs = parseInt(document.getElementById('task-runs').value) || 0;
  const enabled = document.getElementById('task-enabled').checked;
  const deleteAfterExecution = document.getElementById('task-delete-after').checked;
  const deleteAfterRunsCount = document.getElementById('task-delete-after-runs').checked;
  
  if (!name) {
    showNotification('Please enter a task name', 'error');
    return;
  }
  
  if (action === 'COMMAND' && !command) {
    showNotification('Please enter a command', 'error');
    return;
  }
  
  if (deleteAfterRunsCount && runs === 0) {
    showNotification('Please set a run limit when using "Delete after runs"', 'error');
    return;
  }
  
  try {
    const taskData = {
      name,
      action,
      interval,
      command,
      runs,
      enabled,
      deleteAfterExecution,
      deleteAfterRunsCount
    };
    
    if (editingTaskId) {
      await apiRequest(`/api/servers/${currentServerId}/tasks/${editingTaskId}`, {
        method: 'PUT',
        body: JSON.stringify(taskData)
      });
      showNotification('Task updated successfully', 'success');
    } else {
      await apiRequest(`/api/servers/${currentServerId}/tasks`, {
        method: 'POST',
        body: JSON.stringify(taskData)
      });
      showNotification('Task created successfully', 'success');
    }
    
    closeTaskModal();
    loadTasks();
  } catch (error) {
    console.error('Failed to save task:', error);
    showNotification('Failed to save task: ' + error.message, 'error');
  }
}

async function deleteTask(taskId) {
  if (!currentServerId || !taskId) return;
  
  if (!await confirmAction('Are you sure you want to delete this task?', { title: 'Delete Task', icon: '🗑️', okText: 'Delete' })) {
    return;
  }
  
  try {
    await apiRequest(`/api/servers/${currentServerId}/tasks/${taskId}`, {
      method: 'DELETE'
    });
    
    showNotification('Task deleted successfully', 'success');
    loadTasks();
  } catch (error) {
    console.error('Failed to delete task:', error);
    showNotification('Failed to delete task', 'error');
  }
}

// ==================== Tab Switching ====================

function switchTab(tabName) {
  document.querySelectorAll('.tab-button').forEach(btn => {
    btn.classList.remove('active');
  });
  document.querySelectorAll('.tab-content').forEach(content => {
    content.classList.remove('active');
  });
  
  document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
  document.getElementById(`${tabName}-tab`).classList.add('active');
  
  // Load data when switching tabs
  if (tabName === 'files') {
    loadFiles(currentPath);
  } else if (tabName === 'backups') {
    loadBackups();
  } else if (tabName === 'players') {
    loadAllPlayerData();
  } else if (tabName === 'mods') {
    loadMods();
  } else if (tabName === 'properties') {
    loadProperties();
  } else if (tabName === 'logs') {
    loadLogs();
  } else if (tabName === 'tasks') {
    loadTasks();
  } else if (tabName === 'resourcepack') {
    loadResourcePack();
  } else if (tabName === 'quickcmds') {
    loadCannedCommands();
    loadScheduledMessages();
  } else if (tabName === 'terminal') {
    loadCannedCommands();
  }
}

// ==================== Mods Management ====================

// ==================== Mods pagination state ====================
let _allPlugins = [];
let _allMods = [];
let _pluginsPage = 1;
let _modsPage = 1;

async function loadMods() {
  if (!currentServerId) return;
  
  showTableSkeleton('plugins-list', 4, 3);
  showTableSkeleton('mods-list', 4, 3);
  
  try {
    const data = await apiRequest(`/api/servers/${currentServerId}/mods`);
    
    _allPlugins = data.plugins || [];
    _allMods = data.mods || [];
    _pluginsPage = 1;
    _modsPage = 1;
    
    renderPluginsPage();
    renderModsPage();
  } catch (error) {
    console.error('Failed to load mods:', error);
    document.getElementById('plugins-list').innerHTML = '<tr><td colspan="4" class="empty-message error">Failed to load plugins</td></tr>';
    document.getElementById('mods-list').innerHTML = '<tr><td colspan="4" class="empty-message error">Failed to load mods</td></tr>';
    document.getElementById('plugins-pagination').innerHTML = '';
    document.getElementById('mods-pagination').innerHTML = '';
  }
}

function renderPluginsPage() {
  const tbody = document.getElementById('plugins-list');
  if (_allPlugins.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty-message">No plugins installed</td></tr>';
    document.getElementById('plugins-pagination').innerHTML = '';
    return;
  }
  tbody.innerHTML = '';
  const start = (_pluginsPage - 1) * PAGE_SIZE;
  _allPlugins.slice(start, start + PAGE_SIZE).forEach(plugin => {
    tbody.appendChild(createModRow(plugin, 'plugins'));
  });
  renderPagination('plugins-pagination', _allPlugins.length, _pluginsPage, setPluginsPage);
}

function setPluginsPage(page) { _pluginsPage = page; renderPluginsPage(); }

function renderModsPage() {
  const tbody = document.getElementById('mods-list');
  if (_allMods.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty-message">No mods installed</td></tr>';
    document.getElementById('mods-pagination').innerHTML = '';
    return;
  }
  tbody.innerHTML = '';
  const start = (_modsPage - 1) * PAGE_SIZE;
  _allMods.slice(start, start + PAGE_SIZE).forEach(mod => {
    tbody.appendChild(createModRow(mod, 'mods'));
  });
  renderPagination('mods-pagination', _allMods.length, _modsPage, setModsPage);
}

function setModsPage(page) { _modsPage = page; renderModsPage(); }

function createModRow(mod, type) {
  const row = document.createElement('tr');
  
  const nameCell = document.createElement('td');
  nameCell.innerHTML = `<span class="file-icon">📦</span> ${escapeHtml(mod.name)}`;
  
  const sizeCell = document.createElement('td');
  sizeCell.textContent = formatBytes(mod.size);
  
  const modifiedCell = document.createElement('td');
  modifiedCell.textContent = mod.modified ? new Date(mod.modified).toLocaleString() : '-';
  
  const actionsCell = document.createElement('td');
  const actionsDiv = document.createElement('div');
  actionsDiv.className = 'file-actions-cell';
  
  const toggleBtn = document.createElement('button');
  const isEnabled = !mod.name.endsWith('.disabled');
  toggleBtn.textContent = isEnabled ? 'Disable' : 'Enable';
  toggleBtn.className = `btn btn-small action-btn ${isEnabled ? '' : 'btn-success'}`;
  toggleBtn.onclick = () => toggleMod(mod.name, type, isEnabled);
  actionsDiv.appendChild(toggleBtn);
  
  const deleteBtn = document.createElement('button');
  deleteBtn.textContent = 'Delete';
  deleteBtn.className = 'btn btn-danger btn-small action-btn';
  deleteBtn.onclick = () => deleteMod(mod.name, type);
  actionsDiv.appendChild(deleteBtn);
  
  actionsCell.appendChild(actionsDiv);
  
  row.appendChild(nameCell);
  row.appendChild(sizeCell);
  row.appendChild(modifiedCell);
  row.appendChild(actionsCell);
  
  return row;
}

async function toggleMod(filename, type, isEnabled) {
  if (!currentServerId) return;
  
  const action = isEnabled ? 'disable' : 'enable';
  
  try {
    await apiRequest(`/api/servers/${currentServerId}/mods/${type}/${encodeURIComponent(filename)}/${action}`, {
      method: 'POST'
    });
    showNotification(`Mod ${action}d successfully`, 'success');
    loadMods();
  } catch (error) {
    console.error('Failed to toggle mod:', error);
  }
}

async function deleteMod(filename, type) {
  if (!currentServerId) return;
  
  if (!await confirmAction(`Are you sure you want to delete "${filename}"? This cannot be undone.`, { title: 'Delete Mod', icon: '🗑️', okText: 'Delete' })) {
    return;
  }
  
  try {
    await apiRequest(`/api/servers/${currentServerId}/mods/${type}/${encodeURIComponent(filename)}`, {
      method: 'DELETE'
    });
    showNotification('Mod deleted successfully', 'success');
    loadMods();
  } catch (error) {
    console.error('Failed to delete mod:', error);
  }
}

async function uploadMod(file, type) {
  if (!currentServerId || !file) return;
  
  const formData = new FormData();
  formData.append('file', file);
  formData.append('type', type);
  
  try {
    const response = await fetch(`/api/servers/${currentServerId}/mods/upload`, {
      method: 'POST',
      headers: window.csrfToken ? { 'X-CSRF-Token': window.csrfToken } : {},
      body: formData
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Upload failed');
    }
    
    showNotification('Mod uploaded successfully', 'success');
    loadMods();
  } catch (error) {
    console.error('Failed to upload mod:', error);
    showNotification('Failed to upload mod: ' + error.message, 'error');
  }
}

function showModUploadDialog() {
  return new Promise((resolve) => {
    // Remove existing modal if any
    const existing = document.getElementById('mod-upload-dialog');
    if (existing) existing.remove();
    
    const modal = document.createElement('div');
    modal.id = 'mod-upload-dialog';
    modal.className = 'modal active';
    modal.innerHTML = `
      <div class="modal-content modal-small">
        <div class="modal-header">
          <h2>📦 Upload Mod/Plugin</h2>
          <button class="close-btn" onclick="this.closest('.modal').remove()">&times;</button>
        </div>
        <div class="modal-body">
          <p>Where would you like to upload the file(s)?</p>
          <div class="mod-upload-choices">
            <button class="btn btn-primary" id="upload-to-plugins">
              🔌 Plugins Folder
              <small>For Bukkit/Spigot/Paper plugins</small>
            </button>
            <button class="btn btn-primary" id="upload-to-mods">
              🔧 Mods Folder
              <small>For Forge/NeoForge/Fabric mods</small>
            </button>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn" onclick="this.closest('.modal').remove()">Cancel</button>
        </div>
      </div>
    `;
    
    document.body.appendChild(modal);
    
    document.getElementById('upload-to-plugins').onclick = () => {
      modal.remove();
      resolve('plugins');
    };
    
    document.getElementById('upload-to-mods').onclick = () => {
      modal.remove();
      resolve('mods');
    };
    
    // Cancel on backdrop click
    modal.onclick = (e) => {
      if (e.target === modal) {
        modal.remove();
        resolve(null);
      }
    };
  });
}

// ==================== Modrinth Browser ====================

let _modrinthSearchPage = 0;
let _modrinthLastQuery  = {};
const MODRINTH_PAGE_SIZE = 20;

function openModrinthSearch() {
  if (!currentServerId) return;

  // Pre-populate loader/version from server config if available
  const server = servers.find(s => s.id === currentServerId);
  if (server) {
    const loaderMap = {
      paper: 'paper', purpur: 'purpur', folia: 'folia', spigot: 'spigot',
      fabric: 'fabric', forge: 'forge', neoforge: 'neoforge',
    };
    const typeEl = document.getElementById('modrinth-type');
    const loaderEl = document.getElementById('modrinth-loader');
    const mcVerEl = document.getElementById('modrinth-mcversion');

    if (server.serverType && loaderMap[server.serverType.toLowerCase()]) {
      loaderEl.value = loaderMap[server.serverType.toLowerCase()];
      // Plugins loaders imply plugin type
      if (['paper','purpur','folia','spigot'].includes(server.serverType.toLowerCase())) {
        typeEl.value = 'plugin';
      } else {
        typeEl.value = 'mod';
      }
    }
    if (server.version && server.version !== 'unknown') {
      mcVerEl.value = server.version;
    }
  }

  document.getElementById('modrinth-modal').classList.add('active');
  document.getElementById('modrinth-query').focus();
}

function closeModrinthSearch() {
  document.getElementById('modrinth-modal').classList.remove('active');
}

async function doModrinthSearch(pageOffset = 0) {
  if (!currentServerId) return;

  const query     = document.getElementById('modrinth-query').value.trim();
  const type      = document.getElementById('modrinth-type').value;
  const loader    = document.getElementById('modrinth-loader').value;
  const mcVersion = document.getElementById('modrinth-mcversion').value.trim();

  _modrinthSearchPage = pageOffset;
  _modrinthLastQuery  = { query, type, loader, mcVersion };

  const resultsEl = document.getElementById('modrinth-results');
  resultsEl.innerHTML = '<div class="table-loading-overlay"><div class="loading-spinner"></div><span>Searching…</span></div>';
  document.getElementById('modrinth-pagination').innerHTML = '';

  try {
    const params = new URLSearchParams({
      query,
      projectType: type,
      loader,
      mcVersion:  mcVersion,
      limit:      MODRINTH_PAGE_SIZE,
      offset:     pageOffset,
    });

    const data = await apiRequest(`/api/servers/${currentServerId}/mods/search?${params}`);

    if (!data.hits || data.hits.length === 0) {
      resultsEl.innerHTML = '<p class="modrinth-hint">No results found. Try a different search.</p>';
      return;
    }

    resultsEl.innerHTML = '';
    data.hits.forEach(hit => {
      const card = document.createElement('div');
      card.className = 'modrinth-card';

      const iconHtml = hit.iconUrl
        ? `<img class="modrinth-icon" src="${escapeHtml(hit.iconUrl)}" alt="" loading="lazy" onerror="this.style.display='none'">`
        : `<div class="modrinth-icon-placeholder">📦</div>`;

      const dlFormatted = hit.downloads >= 1_000_000
        ? (hit.downloads / 1_000_000).toFixed(1) + 'M'
        : hit.downloads >= 1000 ? (hit.downloads / 1000).toFixed(1) + 'K'
        : String(hit.downloads);

      card.innerHTML = `
        ${iconHtml}
        <div class="modrinth-info">
          <div class="modrinth-title">${escapeHtml(hit.title)}</div>
          <div class="modrinth-author">by ${escapeHtml(hit.author || '')}</div>
          <div class="modrinth-desc">${escapeHtml(hit.description || '')}</div>
          <div class="modrinth-meta">
            <span class="modrinth-downloads">⬇️ ${dlFormatted}</span>
            ${hit.categories.slice(0, 3).map(c => `<span class="badge badge-secondary">${escapeHtml(c)}</span>`).join('')}
          </div>
          <button class="btn btn-success btn-small modrinth-install-btn"
                  onclick="openModrinthVersionModal('${escapeHtml(hit.projectId)}', '${escapeHtml(hit.title)}')">
            Install
          </button>
        </div>
      `;
      resultsEl.appendChild(card);
    });

    // Pagination
    const total = data.totalHits;
    if (total > MODRINTH_PAGE_SIZE) {
      const paginEl = document.getElementById('modrinth-pagination');
      const currentPage = Math.floor(pageOffset / MODRINTH_PAGE_SIZE) + 1;
      const totalPages  = Math.ceil(total / MODRINTH_PAGE_SIZE);

      let html = `<button ${pageOffset === 0 ? 'disabled' : ''} onclick="doModrinthSearch(${Math.max(0, pageOffset - MODRINTH_PAGE_SIZE)})">‹ Prev</button>`;
      html += `<span class="pagination-info">Page ${currentPage} of ${totalPages} (${total} results)</span>`;
      html += `<button ${pageOffset + MODRINTH_PAGE_SIZE >= total ? 'disabled' : ''} onclick="doModrinthSearch(${pageOffset + MODRINTH_PAGE_SIZE})">Next ›</button>`;
      paginEl.innerHTML = html;
    }

  } catch (error) {
    resultsEl.innerHTML = `<p class="modrinth-hint" style="color:#f45c43;">Failed to search Modrinth: ${escapeHtml(error.message)}</p>`;
    console.error('Modrinth search failed:', error);
  }
}

// ==================== Modrinth Version Picker ====================

let _modrinthInstallProjectId = '';

async function openModrinthVersionModal(projectId, projectTitle) {
  _modrinthInstallProjectId = projectId;

  document.getElementById('modrinth-version-title').textContent = `Install: ${projectTitle}`;
  document.getElementById('modrinth-version-list').innerHTML = '<p class="empty-message">Loading versions…</p>';
  document.getElementById('modrinth-version-modal').classList.add('active');

  // Pre-select install folder based on search type
  const type = document.getElementById('modrinth-type').value;
  document.getElementById('modrinth-install-folder').value = (type === 'plugin') ? 'plugins' : 'mods';

  const loader    = document.getElementById('modrinth-loader').value;
  const mcVersion = document.getElementById('modrinth-mcversion').value.trim();

  try {
    const params = new URLSearchParams({ loader, mcVersion: mcVersion });
    const data = await apiRequest(`/api/servers/${currentServerId}/mods/modrinth/versions/${encodeURIComponent(projectId)}?${params}`);

    const versions = data.versions || [];
    if (versions.length === 0) {
      document.getElementById('modrinth-version-list').innerHTML =
        '<p class="empty-message">No compatible versions found for the selected loader/MC version.</p>';
      return;
    }

    const listEl = document.getElementById('modrinth-version-list');
    listEl.innerHTML = '';
    versions.slice(0, 30).forEach(v => { // cap at 30 to avoid giant lists
      const row = document.createElement('div');
      row.className = 'modrinth-version-row';
      row.innerHTML = `
        <span class="modrinth-ver-name">${escapeHtml(v.name || v.versionNumber)}</span>
        <span class="modrinth-ver-loaders">${v.loaders.join(', ')}</span>
        <span class="modrinth-ver-mc">${v.gameVersions.slice(-3).join(', ')}</span>
        <span class="modrinth-ver-size">${formatBytes(v.size)}</span>
        <button class="btn btn-success btn-small"
                onclick="installModrinthVersion(
                  '${escapeHtml(v.url)}',
                  '${escapeHtml(v.filename)}',
                  '${escapeHtml(v.sha512 || '')}')">
          Install
        </button>
      `;
      listEl.appendChild(row);
    });
  } catch (error) {
    document.getElementById('modrinth-version-list').innerHTML =
      `<p class="empty-message" style="color:#f45c43;">Failed to load versions: ${escapeHtml(error.message)}</p>`;
    console.error('Failed to load Modrinth versions:', error);
  }
}

function closeModrinthVersionModal() {
  document.getElementById('modrinth-version-modal').classList.remove('active');
}

async function installModrinthVersion(url, filename, sha512) {
  if (!currentServerId) return;

  const modType = document.getElementById('modrinth-install-folder').value;

  // Show in-progress state
  const btn = event.target;
  const origText = btn.textContent;
  btn.textContent = 'Installing…';
  btn.disabled = true;

  try {
    await apiRequest(`/api/servers/${currentServerId}/mods/modrinth/install`, {
      method: 'POST',
      body: JSON.stringify({ url, filename, modType: modType, sha512 }),
    });

    showNotification(`${filename} installed to ${modType}/`, 'success');
    btn.textContent = '✅ Installed';
    closeModrinthVersionModal();
    loadMods();
  } catch (error) {
    showNotification(`Install failed: ${error.message}`, 'error');
    btn.textContent = origText;
    btn.disabled = false;
    console.error('Modrinth install failed:', error);
  }
}

// ==================== Mod Update Checker ====================

async function checkModUpdates() {
  if (!currentServerId) return;

  const btn = document.getElementById('check-updates-btn');
  if (btn) { btn.textContent = '⏳ Checking…'; btn.disabled = true; }

  const server     = servers.find(s => s.id === currentServerId);
  const loader     = (server?.serverType || '').toLowerCase();
  const mcVersion  = (server?.version && server.version !== 'unknown') ? server.version : '';

  const resultsEl = document.getElementById('mods-update-results');
  resultsEl.style.display = 'none';

  try {
    const params = new URLSearchParams({ loader, mcVersion: mcVersion });
    const data = await apiRequest(`/api/servers/${currentServerId}/mods/updates?${params}`);

    const updates = data.updates || [];

    if (updates.length === 0) {
      showNotification('All mods are up-to-date (or not found on Modrinth)', 'success');
      resultsEl.style.display = 'none';
    } else {
      let html = `<h4>🔄 ${updates.length} update${updates.length !== 1 ? 's' : ''} available</h4>`;
      updates.forEach(u => {
        html += `
          <div class="update-item">
            <span class="update-filename">📦 ${escapeHtml(u.currentFilename)}</span>
            <span class="update-arrow">→</span>
            <span class="update-new-ver">${escapeHtml(u.versionNumber)}</span>
            <span class="update-arrow">(${escapeHtml(u.filename)})</span>
            <button class="btn btn-success btn-small"
                    onclick="applyModUpdate(
                      '${escapeHtml(u.url)}',
                      '${escapeHtml(u.filename)}',
                      '${escapeHtml(u.sha512 || '')}',
                      '${escapeHtml(u.folder)}',
                      '${escapeHtml(u.currentFilename)}',
                      this)">
              Update
            </button>
          </div>
        `;
      });
      resultsEl.innerHTML = html;
      resultsEl.style.display = 'block';
    }
  } catch (error) {
    showNotification(`Update check failed: ${error.message}`, 'error');
    console.error('Update check failed:', error);
  } finally {
    if (btn) { btn.textContent = '🔄 Check Updates'; btn.disabled = false; }
  }
}

async function applyModUpdate(url, filename, sha512, folder, currentFilename, btn) {
  if (!currentServerId) return;

  const confirmed = await confirmAction(
    `Update "${currentFilename}" to "${filename}"?\n\nThe old file will be replaced.`,
    { title: 'Update Mod', icon: '🔄', okText: 'Update', okClass: 'btn-success' }
  );
  if (!confirmed) return;

  const origText = btn.textContent;
  btn.textContent = '⏳';
  btn.disabled = true;

  try {
    // Install new version
    await apiRequest(`/api/servers/${currentServerId}/mods/modrinth/install`, {
      method: 'POST',
      body: JSON.stringify({ url, filename, modType: folder, sha512 }),
    });

    // Delete old file if the filename is different
    if (filename !== currentFilename) {
      try {
        await apiRequest(`/api/servers/${currentServerId}/mods/${folder}/${encodeURIComponent(currentFilename)}`, {
          method: 'DELETE'
        });
      } catch (_) { /* best effort — new file already installed */ }
    }

    showNotification(`Updated to ${filename}`, 'success');
    btn.closest('.update-item').remove();
    const remaining = document.querySelectorAll('.update-item').length;
    if (remaining === 0) document.getElementById('mods-update-results').style.display = 'none';
    loadMods();
  } catch (error) {
    showNotification(`Update failed: ${error.message}`, 'error');
    btn.textContent = origText;
    btn.disabled = false;
  }
}

// ==================== Player Management ====================

let currentEditingOpUuid = null;

function isBedrockServer() {
  return currentServerCategory === 'bedrock';
}

// Bedrock stores this data differently everywhere: operators in permissions.json
// (keyed by XUID), the allow list in allowlist.json, player data inside the world's
// LevelDB, and no ban list at all — the panel keeps that one itself and enforces it
// by kicking on connect. Those three sections get Bedrock columns/fields here.
// Player data and IP bans have no Bedrock equivalent at all and stay hidden.
function applyPlayersTabForCategory() {
  const bedrock = isBedrockServer();
  const hideOnBedrock = bedrock ? 'none' : '';

  const notice = document.getElementById('bedrock-players-notice');
  if (notice) notice.style.display = bedrock ? '' : 'none';

  ['playerdata-section', 'banned-ips-section'].forEach(id => {
    const section = document.getElementById(id);
    if (section) section.style.display = hideOnBedrock;
  });

  // Bans: the panel's own list on Bedrock, keyed by XUID rather than UUID
  const bannedThead = document.getElementById('banned-thead');
  if (bannedThead) {
    bannedThead.innerHTML = `<tr><th>Player</th><th>${bedrock ? 'XUID' : 'UUID'}</th><th>Reason</th>`
      + '<th>Expires</th><th>Banned By</th><th>Actions</th></tr>';
  }
  setDisplay('banned-bedrock-note', bedrock);

  // Operators: XUID + Bedrock permission names instead of UUID + level 1-4
  setDisplay('ops-levels-java', !bedrock);
  setDisplay('ops-levels-bedrock', bedrock);
  const opsThead = document.getElementById('ops-thead');
  if (opsThead) {
    opsThead.innerHTML = bedrock
      ? '<tr><th>Player</th><th>XUID</th><th>Permission</th><th>Actions</th></tr>'
      : '<tr><th>Player</th><th>UUID</th><th>Level</th><th>Bypass Limit</th><th>Actions</th></tr>';
  }

  // Allow list: name + XUID + "ignores player limit", no UUID
  const wlTitle = document.getElementById('whitelist-section-title');
  if (wlTitle) wlTitle.textContent = bedrock ? '📝 Allow List' : '📝 Whitelist';
  const wlThead = document.getElementById('whitelist-thead');
  if (wlThead) {
    wlThead.innerHTML = bedrock
      ? '<tr><th>Player</th><th>XUID</th><th>Ignores Player Limit</th><th>Actions</th></tr>'
      : '<tr><th>Player</th><th>UUID</th><th>Actions</th></tr>';
  }
  setDisplay('whitelist-bedrock-note', bedrock);
}

function setDisplay(id, visible) {
  const el = document.getElementById(id);
  if (el) el.style.display = visible ? '' : 'none';
}

async function loadAllPlayerData() {
  if (!currentServerId) return;

  applyPlayersTabForCategory();

  if (isBedrockServer()) {
    // No player-data files and no IP bans on Bedrock — skip those endpoints
    await Promise.all([
      loadOnlinePlayers(),
      loadOperators(),
      loadWhitelist(),
      loadBannedPlayers()
    ]);
    return;
  }

  await Promise.all([
    loadOnlinePlayers(),
    loadOperators(),
    loadPlayerData(),
    loadWhitelist(),
    loadBannedPlayers(),
    loadBannedIPs()
  ]);
}

async function loadOperators() {
  if (!currentServerId) return;

  const bedrock = isBedrockServer();
  const cols = bedrock ? 4 : 5;
  const tbody = document.getElementById('ops-list');
  showTableSkeleton('ops-list', cols, 3);

  try {
    const data = await apiRequest(`/api/servers/${currentServerId}/players/ops`);
    const ops = data.operators || [];

    if (ops.length === 0) {
      tbody.innerHTML = `<tr><td colspan="${cols}" class="empty-message">${bedrock ? 'No permission entries — everyone gets the server default' : 'No operators configured'}</td></tr>`;
      return;
    }

    if (bedrock) {
      // permissions.json is keyed by XUID; the gamertag is only known once the
      // player has connected at least once with the panel attached.
      tbody.innerHTML = ops.map(op => {
        const label = op.name || '(unknown gamertag)';
        return `
        <tr>
          <td><strong>${escapeHtml(label)}</strong></td>
          <td class="uuid-cell">${escapeHtml(op.xuid)}</td>
          <td><span class="level-badge level-${op.permission === 'operator' ? 4 : (op.permission === 'visitor' ? 1 : 2)}">${escapeHtml(op.permission)}</span></td>
          <td class="actions-cell">
            <button class="btn btn-small" onclick="editBedrockPermission('${escapeAttr(op.xuid)}', '${escapeAttr(label)}', '${escapeAttr(op.permission)}')">Edit</button>
            <button class="btn btn-danger btn-small" onclick="removeOperator('${escapeAttr(op.xuid)}', '${escapeAttr(label)}')">Remove</button>
          </td>
        </tr>
      `;
      }).join('');
      return;
    }

    tbody.innerHTML = ops.map(op => `
      <tr>
        <td><strong>${escapeHtml(op.name)}</strong></td>
        <td class="uuid-cell">${escapeHtml(op.uuid)}</td>
        <td>
          <span class="level-badge level-${op.level}">Level ${op.level}</span>
        </td>
        <td>${op.bypassesPlayerLimit ? '✅' : '❌'}</td>
        <td class="actions-cell">
          <button class="btn btn-small" onclick="editOperator('${op.uuid}', '${escapeHtml(op.name)}', ${op.level}, ${op.bypassesPlayerLimit})">Edit</button>
          <button class="btn btn-danger btn-small" onclick="removeOperator('${op.uuid}', '${escapeHtml(op.name)}')">Remove</button>
        </td>
      </tr>
    `).join('');
  } catch (error) {
    tbody.innerHTML = `<tr><td colspan="${cols}" class="empty-message error">Failed to load operators</td></tr>`;
  }
}

// ==================== Player Data pagination state ====================
let _allPlayerRows = [];
let _playerDataPage = 1;

async function loadPlayerData() {
  if (!currentServerId) return;
  
  const tbody = document.getElementById('playerdata-list');
  showTableSkeleton('playerdata-list', 4, 5);
  _playerDataPage = 1;
  
  try {
    const [playerDataResponse, opsResponse, whitelistResponse, bannedResponse] = await Promise.all([
      apiRequest(`/api/servers/${currentServerId}/players/playerdata`),
      apiRequest(`/api/servers/${currentServerId}/players/ops`),
      apiRequest(`/api/servers/${currentServerId}/players/whitelist`),
      apiRequest(`/api/servers/${currentServerId}/players/banned`)
    ]);
    
    const players = playerDataResponse.players || [];
    const ops = opsResponse.operators || [];
    const whitelist = whitelistResponse.whitelist || [];
    const banned = bannedResponse.banned || [];
    
    if (playerDataResponse.message) {
      tbody.innerHTML = `<tr><td colspan="4" class="empty-message">${escapeHtml(playerDataResponse.message)}</td></tr>`;
      document.getElementById('playerdata-pagination').innerHTML = '';
      return;
    }
    
    if (players.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty-message">No player data found</td></tr>';
      document.getElementById('playerdata-pagination').innerHTML = '';
      return;
    }
    
    const whitelistUuids = new Set(whitelist.map(p => p.uuid));
    const bannedUuids = new Set(banned.map(p => p.uuid));

    _allPlayerRows = players.map(player => {
      const op = ops.find(o => o.uuid === player.uuid);
      const opButton = op 
        ? `<button class="btn btn-small btn-danger" onclick="removeOperator('${player.uuid}', '${escapeHtml(op.name)}')">Remove OP</button>`
        : `<button class="btn btn-small btn-success" onclick="makePlayerOp('${player.uuid}')">Make OP</button>`;

      const wlButton = whitelistUuids.has(player.uuid)
        ? `<button class="btn btn-small btn-secondary" disabled title="Already whitelisted">✓ WL</button>`
        : `<button class="btn btn-small" onclick="whitelistPlayerByUuid('${player.uuid}')">Whitelist</button>`;

      const banButton = bannedUuids.has(player.uuid)
        ? `<button class="btn btn-small btn-secondary" disabled title="Already banned">Banned</button>`
        : `<button class="btn btn-small btn-danger" onclick="banPlayerByUuid('${player.uuid}')">Ban</button>`;
      
      return `
        <tr>
          <td class="uuid-cell">${escapeHtml(player.uuid)}</td>
          <td>${new Date(player.modified).toLocaleString()}</td>
          <td>${formatBytes(player.size)}</td>
          <td class="actions-cell">
            <button class="btn btn-small" onclick="openPlayerNbtEditor('${player.uuid}', '${escapeHtml(player.path || '')}')">Edit NBT</button>
            <button class="btn btn-small" onclick="viewPlayerStats('${player.uuid}')">📊 Stats</button>
            <button class="btn btn-small" onclick="viewPlayerInventory('${player.uuid}')">🎒 Inventory</button>
            ${opButton}
            ${wlButton}
            ${banButton}
          </td>
        </tr>
      `;
    });
    
    renderPlayerDataPage();
  } catch (error) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty-message error">Failed to load player data</td></tr>';
    document.getElementById('playerdata-pagination').innerHTML = '';
  }
}

function renderPlayerDataPage() {
  const tbody = document.getElementById('playerdata-list');
  const start = (_playerDataPage - 1) * PAGE_SIZE;
  tbody.innerHTML = _allPlayerRows.slice(start, start + PAGE_SIZE).join('');
  renderPagination('playerdata-pagination', _allPlayerRows.length, _playerDataPage, setPlayerDataPage);
}

function setPlayerDataPage(page) { _playerDataPage = page; renderPlayerDataPage(); }

async function loadWhitelist() {
  if (!currentServerId) return;

  const bedrock = isBedrockServer();
  const cols = bedrock ? 4 : 3;
  const tbody = document.getElementById('whitelist-list');
  showTableSkeleton('whitelist-list', cols, 3);

  try {
    const [data, statusData] = await Promise.all([
      apiRequest(`/api/servers/${currentServerId}/players/whitelist`),
      apiRequest(`/api/servers/${currentServerId}/players/whitelist-status`).catch(() => ({ enabled: false, available: false }))
    ]);
    const whitelist = data.whitelist || [];

    // Update toggle button state
    updateWhitelistToggleBtn(statusData.enabled, statusData.available !== false);

    if (whitelist.length === 0) {
      tbody.innerHTML = `<tr><td colspan="${cols}" class="empty-message">${bedrock ? 'Allow list is empty' : 'Whitelist is empty'}</td></tr>`;
      return;
    }

    if (bedrock) {
      // allowlist.json entries have no UUID — the XUID is the key once Bedrock
      // has filled it in, and the gamertag identifies the entry until then.
      tbody.innerHTML = whitelist.map(player => {
        const id = player.xuid || player.name;
        return `
        <tr>
          <td><strong>${escapeHtml(player.name)}</strong></td>
          <td class="uuid-cell">${escapeHtml(player.xuid || '—')}</td>
          <td>${player.ignoresPlayerLimit ? '✅' : '❌'}</td>
          <td class="actions-cell">
            <button class="btn btn-danger btn-small" onclick="removeFromWhitelist('${escapeAttr(encodeURIComponent(id))}', '${escapeAttr(player.name)}')">Remove</button>
          </td>
        </tr>
      `;
      }).join('');
      return;
    }

    tbody.innerHTML = whitelist.map(player => `
      <tr>
        <td><strong>${escapeHtml(player.name)}</strong></td>
        <td class="uuid-cell">${escapeHtml(player.uuid)}</td>
        <td class="actions-cell">
          <button class="btn btn-danger btn-small" onclick="removeFromWhitelist('${player.uuid}', '${escapeHtml(player.name)}')">Remove</button>
        </td>
      </tr>
    `).join('');
  } catch (error) {
    tbody.innerHTML = `<tr><td colspan="${cols}" class="empty-message error">Failed to load ${bedrock ? 'allow list' : 'whitelist'}</td></tr>`;
  }
}

function whitelistLabel() {
  return isBedrockServer() ? 'Allow list' : 'Whitelist';
}

function updateWhitelistToggleBtn(enabled, available) {
  const btn = document.getElementById('whitelist-toggle-btn');
  if (!btn) return;
  const short = isBedrockServer() ? 'AL' : 'WL';
  if (!available) {
    btn.textContent = `${short}: N/A`;
    btn.className = 'btn btn-small btn-secondary';
    btn.disabled = true;
    btn.title = 'server.properties not found';
    return;
  }
  btn.disabled = false;
  if (enabled) {
    btn.textContent = `✅ ${short}: ON`;
    btn.className = 'btn btn-small btn-success';
    btn.title = `${whitelistLabel()} is enabled — click to disable`;
  } else {
    btn.textContent = `⬜ ${short}: OFF`;
    btn.className = 'btn btn-small';
    btn.title = `${whitelistLabel()} is disabled — click to enable`;
  }
}

async function toggleWhitelistSetting() {
  try {
    const result = await apiRequest(`/api/servers/${currentServerId}/players/whitelist-toggle`, {
      method: 'PATCH'
    });
    updateWhitelistToggleBtn(result.enabled, true);
    showNotification(`${whitelistLabel()} ${result.enabled ? 'enabled' : 'disabled'}. Restart server for changes to take effect.`, 'success');
  } catch (error) {
    // Error shown by apiRequest
  }
}

async function whitelistPlayerByUuid(uuid) {
  try {
    const result = await apiRequest(`/api/servers/${currentServerId}/players/whitelist`, {
      method: 'POST',
      body: JSON.stringify({ uuid })
    });
    showNotification(result.message || 'Player added to whitelist', 'success');
    loadAllPlayerData();
  } catch (error) {
    // Error shown by apiRequest
  }
}

async function banPlayerByUuid(uuid) {
  const reason = prompt('Reason for ban (leave blank for default):');
  if (reason === null) return; // cancelled
  try {
    const result = await apiRequest(`/api/servers/${currentServerId}/players/banned`, {
      method: 'POST',
      body: JSON.stringify({ uuid, reason: reason.trim() || 'Banned By Admin' })
    });
    showNotification(result.message || 'Player has been banned', 'success');
    loadAllPlayerData();
  } catch (error) {
    // Error shown by apiRequest
  }
}

async function loadBannedPlayers() {
  if (!currentServerId) return;
  
  const tbody = document.getElementById('banned-list');
  showTableSkeleton('banned-list', 6, 3);
  
  try {
    const data = await apiRequest(`/api/servers/${currentServerId}/players/banned`);
    const banned = data.banned || [];
    
    if (banned.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-message">No banned players</td></tr>';
      return;
    }
    
    // Bedrock entries are keyed by XUID — or by gamertag until the player has
    // been seen once, since Bedrock only reveals an XUID on connect.
    const bedrock = isBedrockServer();
    tbody.innerHTML = banned.map(player => {
      const expiresDisplay = (!player.expires || player.expires === 'forever')
        ? '<span class="badge badge-danger">Permanent</span>'
        : escapeHtml(player.expires);
      const id = bedrock ? (player.xuid || player.name) : player.uuid;
      return `
        <tr>
          <td><strong>${escapeHtml(player.name)}</strong></td>
          <td class="uuid-cell">${escapeHtml((bedrock ? player.xuid : player.uuid) || '—')}</td>
          <td>${escapeHtml(player.reason || 'No reason')}</td>
          <td>${expiresDisplay}</td>
          <td>${escapeHtml(player.source || 'Unknown')}</td>
          <td class="actions-cell">
            <button class="btn btn-success btn-small" onclick="unbanPlayer('${escapeAttr(encodeURIComponent(id))}', '${escapeAttr(player.name)}')">Unban</button>
          </td>
        </tr>
      `;
    }).join('');
  } catch (error) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-message error">Failed to load banned players</td></tr>';
  }
}

// Operator Functions
function openAddOpModal() {
  const bedrock = isBedrockServer();
  // On Bedrock this sets any of visitor/member/operator, not just "add an OP"
  document.getElementById('add-op-title').textContent = bedrock ? 'Set Player Permission' : 'Add Operator';
  document.getElementById('add-op-submit').textContent = bedrock ? 'Save' : 'Add OP';
  document.getElementById('op-player-name').value = '';
  document.getElementById('op-player-name-label').textContent = bedrock ? 'Gamertag' : 'Player Name';
  document.getElementById('op-player-name').placeholder = bedrock ? 'Enter gamertag' : 'Enter player name';
  document.getElementById('op-xuid').value = '';
  document.getElementById('op-permission').value = 'operator';
  document.getElementById('op-level').value = '4';
  document.getElementById('op-bypass-limit').checked = false;
  // Bedrock: XUID + permission name. Java: level 1-4 + bypass-limit flag.
  setDisplay('op-xuid-group', bedrock);
  setDisplay('op-permission-group', bedrock);
  setDisplay('op-level-group', !bedrock);
  setDisplay('op-bypass-group', !bedrock);
  document.getElementById('add-op-modal').classList.add('active');
}

function closeAddOpModal() {
  document.getElementById('add-op-modal').classList.remove('active');
}

async function addOperator() {
  const name = document.getElementById('op-player-name').value.trim();
  const bedrock = isBedrockServer();
  const xuid = document.getElementById('op-xuid').value.trim();

  if (!name && !(bedrock && xuid)) {
    showNotification(bedrock ? 'Please enter a gamertag or XUID' : 'Please enter a player name', 'warning');
    return;
  }

  const payload = bedrock
    ? { name, xuid, permission: document.getElementById('op-permission').value }
    : {
        name,
        level: parseInt(document.getElementById('op-level').value),
        bypassesPlayerLimit: document.getElementById('op-bypass-limit').checked
      };

  try {
    const result = await apiRequest(`/api/servers/${currentServerId}/players/ops`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });

    closeAddOpModal();
    showNotification(result.message || `${name} added as operator`, 'success');
    loadOperators();
  } catch (error) {
    // Error shown by apiRequest
  }
}

function editOperator(uuid, name, level, bypassLimit) {
  currentEditingOpUuid = uuid;
  document.getElementById('edit-op-name').value = name;
  document.getElementById('edit-op-level').value = level;
  document.getElementById('edit-op-bypass').checked = bypassLimit;
  setDisplay('edit-op-permission-group', false);
  setDisplay('edit-op-level-group', true);
  setDisplay('edit-op-bypass-group', true);
  document.getElementById('edit-op-modal').classList.add('active');
}

// Bedrock's permissions.json has no level or bypass flag — just one of
// visitor/member/operator, keyed by XUID.
function editBedrockPermission(xuid, name, permission) {
  currentEditingOpUuid = xuid;
  document.getElementById('edit-op-name').value = name;
  document.getElementById('edit-op-permission').value = permission || 'operator';
  setDisplay('edit-op-permission-group', true);
  setDisplay('edit-op-level-group', false);
  setDisplay('edit-op-bypass-group', false);
  document.getElementById('edit-op-modal').classList.add('active');
}

function closeEditOpModal() {
  document.getElementById('edit-op-modal').classList.remove('active');
  currentEditingOpUuid = null;
}

async function saveOperator() {
  if (!currentEditingOpUuid) return;

  const payload = isBedrockServer()
    ? { permission: document.getElementById('edit-op-permission').value }
    : {
        level: parseInt(document.getElementById('edit-op-level').value),
        bypassesPlayerLimit: document.getElementById('edit-op-bypass').checked
      };

  try {
    const result = await apiRequest(`/api/servers/${currentServerId}/players/ops/${currentEditingOpUuid}`, {
      method: 'PUT',
      body: JSON.stringify(payload)
    });

    closeEditOpModal();
    showNotification(result.message || 'Operator updated', 'success');
    loadOperators();
  } catch (error) {
    // Error shown by apiRequest
  }
}

// `uuid` is a Java player UUID, or the XUID of a Bedrock permissions.json entry.
async function removeOperator(uuid, name) {
  const message = isBedrockServer()
    ? `Remove the permission entry for ${name}? They fall back to the server's default permission.`
    : `Remove ${name} from operators?`;
  if (!await confirmAction(message, { title: 'Remove Operator', icon: '👑', okText: 'Remove' })) return;

  try {
    const result = await apiRequest(`/api/servers/${currentServerId}/players/ops/${uuid}`, {
      method: 'DELETE'
    });

    showNotification(result.message || `${name} removed from operators`, 'success');
    loadOperators();
  } catch (error) {
    // Error shown by apiRequest
  }
}

async function makePlayerOp(uuid) {
  try {
    const result = await apiRequest(`/api/servers/${currentServerId}/players/ops`, {
      method: 'POST',
      body: JSON.stringify({ uuid, level: 4, bypassesPlayerLimit: false })
    });

    showNotification(result.message || 'Player added as operator', 'success');
    loadAllPlayerData();
  } catch (error) {
    // Error shown by apiRequest
  }
}

// Whitelist Functions
function openAddWhitelistModal() {
  const bedrock = isBedrockServer();
  document.getElementById('whitelist-player-name').value = '';
  document.getElementById('whitelist-ignores-limit').checked = false;
  document.getElementById('add-whitelist-title').textContent = bedrock ? 'Add to Allow List' : 'Add to Whitelist';
  document.getElementById('whitelist-player-name-label').textContent = bedrock ? 'Gamertag' : 'Player Name';
  document.getElementById('whitelist-player-name').placeholder = bedrock ? 'Enter gamertag' : 'Enter player name';
  // ignoresPlayerLimit is an allowlist.json field with no Java equivalent
  setDisplay('whitelist-ignores-group', bedrock);
  document.getElementById('add-whitelist-modal').classList.add('active');
}

function closeAddWhitelistModal() {
  document.getElementById('add-whitelist-modal').classList.remove('active');
}

async function addToWhitelist() {
  const name = document.getElementById('whitelist-player-name').value.trim();
  const bedrock = isBedrockServer();

  if (!name) {
    showNotification(bedrock ? 'Please enter a gamertag' : 'Please enter a player name', 'warning');
    return;
  }

  const payload = bedrock
    ? { name, ignoresPlayerLimit: document.getElementById('whitelist-ignores-limit').checked }
    : { name };

  try {
    const result = await apiRequest(`/api/servers/${currentServerId}/players/whitelist`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });

    closeAddWhitelistModal();
    showNotification(result.message || `${name} added to the ${whitelistLabel().toLowerCase()}`, 'success');
    loadWhitelist();
  } catch (error) {
    // Error shown by apiRequest
  }
}

// `uuid` is a Java player UUID, or on Bedrock the URI-encoded XUID/gamertag
// that identifies the allowlist.json entry.
async function removeFromWhitelist(uuid, name) {
  const label = whitelistLabel().toLowerCase();
  if (!await confirmAction(`Remove ${name} from the ${label}?`, { title: `Remove from ${whitelistLabel()}`, icon: '📝', okText: 'Remove' })) return;

  try {
    const result = await apiRequest(`/api/servers/${currentServerId}/players/whitelist/${uuid}`, {
      method: 'DELETE'
    });

    showNotification(result.message || `${name} removed from the ${label}`, 'success');
    loadWhitelist();
  } catch (error) {
    // Error shown by apiRequest
  }
}

// Ban Functions
function openBanPlayerModal() {
  const bedrock = isBedrockServer();
  document.getElementById('ban-player-name-label').textContent = bedrock ? 'Gamertag' : 'Player Name';
  document.getElementById('ban-player-name').placeholder = bedrock ? 'Enter gamertag' : 'Enter player name';
  document.getElementById('ban-player-name').value = '';
  document.getElementById('ban-reason').value = '';
  document.getElementById('ban-expires-type').value = 'forever';
  document.getElementById('ban-expires-date-group').style.display = 'none';
  document.getElementById('ban-player-modal').classList.add('active');
}

function closeBanPlayerModal() {
  document.getElementById('ban-player-modal').classList.remove('active');
}

async function banPlayer() {
  const name = document.getElementById('ban-player-name').value.trim();
  const reason = document.getElementById('ban-reason').value.trim() || 'Banned By Admin';
  const expiresType = document.getElementById('ban-expires-type').value;
  let expires = 'forever';
  if (expiresType === 'date') {
    const dateVal = document.getElementById('ban-expires-date').value;
    if (!dateVal) {
      showNotification('Please select an expiry date', 'warning');
      return;
    }
    expires = new Date(dateVal).toISOString();
  }
  
  if (!name) {
    showNotification('Please enter a player name', 'warning');
    return;
  }
  
  try {
    await apiRequest(`/api/servers/${currentServerId}/players/banned`, {
      method: 'POST',
      body: JSON.stringify({ name, reason, expires })
    });
    
    closeBanPlayerModal();
    showNotification(`${name} has been banned`, 'success');
    loadBannedPlayers();
  } catch (error) {
    // Error shown by apiRequest
  }
}

async function unbanPlayer(uuid, name) {
  if (!await confirmAction(`Unban ${name}?`, { title: 'Unban Player', icon: '🚫', okText: 'Unban', okClass: 'btn-success' })) return;
  
  try {
    await apiRequest(`/api/servers/${currentServerId}/players/banned/${uuid}`, {
      method: 'DELETE'
    });
    
    showNotification(`${name} has been unbanned`, 'success');
    loadBannedPlayers();
  } catch (error) {
    // Error shown by apiRequest
  }
}

// Player NBT Editor
// Online Players
async function loadOnlinePlayers() {
  if (!currentServerId) return;
  const tbody = document.getElementById('online-players-list');
  if (!tbody) return;
  try {
    const data = await apiRequest(`/api/servers/${currentServerId}/players/online`);
    const online = data.online || [];
    if (online.length === 0) {
      tbody.innerHTML = '<tr><td colspan="3" class="empty-message">No players online</td></tr>';
      return;
    }
    // Kick is Bedrock's only server-side command, so it sits alongside the
    // panel-enforced ban there; Java's ban already kicks on its own.
    const bedrock = isBedrockServer();
    tbody.innerHTML = online.map(p => `
      <tr>
        <td><strong>${escapeHtml(p.name)}</strong></td>
        <td>${p.since ? new Date(p.since * 1000).toLocaleTimeString() : '—'}</td>
        <td class="actions-cell">
          <button class="btn btn-small" onclick="openMessagePlayersModal('${escapeAttr(p.name)}')">Message</button>
          ${bedrock ? `<button class="btn btn-small" onclick="kickPlayerOnline('${escapeAttr(p.name)}')">Kick</button>` : ''}
          <button class="btn btn-small btn-danger" onclick="banPlayerOnline('${escapeAttr(p.name)}')">Ban</button>
        </td>
      </tr>
    `).join('');
  } catch (error) {
    if (tbody) tbody.innerHTML = '<tr><td colspan="3" class="empty-message">Server offline or no player data</td></tr>';
  }
}

async function kickPlayerOnline(name) {
  const reason = prompt(`Reason for kicking ${name} (optional):`);
  if (reason === null) return; // cancelled
  try {
    const result = await apiRequest(`/api/servers/${currentServerId}/players/kick`, {
      method: 'POST',
      body: JSON.stringify({ name, reason: reason.trim() })
    });
    showNotification(result.message || `${name} has been kicked`, 'success');
    loadOnlinePlayers();
  } catch (error) {
    // Error shown by apiRequest
  }
}

async function banPlayerOnline(name) {
  const reason = prompt(`Reason for banning ${name}:`) ?? '';
  if (reason === null) return;
  try {
    const result = await apiRequest(`/api/servers/${currentServerId}/players/banned`, {
      method: 'POST',
      body: JSON.stringify({ name, reason: reason.trim() || 'Banned By Admin', expires: 'forever' })
    });
    showNotification(result.message || `${name} has been banned`, 'success');
    loadAllPlayerData();
  } catch (error) {
    // Error shown by apiRequest
  }
}

// Player Stats
async function viewPlayerStats(uuid) {
  const modal = document.getElementById('player-stats-modal');
  const content = document.getElementById('player-stats-content');
  content.innerHTML = '<p class="empty-message">Loading...</p>';
  modal.classList.add('active');

  try {
    const data = await apiRequest(`/api/servers/${currentServerId}/players/${uuid}/stats`);
    const h = data.highlights || {};
    const allStats = data.stats || {};

    const playtimeTicks = h.playtimeTicks || 0;
    const playtimeHours = (playtimeTicks / 72000).toFixed(1);
    const distanceKm = ((h.distanceWalkedCm || 0) / 100000).toFixed(2);

    content.innerHTML = `
      <div style="margin-bottom: 16px;">
        <h4 style="margin-bottom: 8px;">Highlights</h4>
        <table class="players-table">
          <tr><td>⏱ Playtime</td><td><strong>${playtimeHours} hours</strong></td></tr>
          <tr><td>💀 Deaths</td><td><strong>${h.deaths || 0}</strong></td></tr>
          <tr><td>⚔️ Player Kills</td><td><strong>${h.playerKills || 0}</strong></td></tr>
          <tr><td>🐾 Mob Kills</td><td><strong>${h.mobKills || 0}</strong></td></tr>
          <tr><td>🏃 Distance Walked</td><td><strong>${distanceKm} km</strong></td></tr>
          <tr><td>⬆️ Jumps</td><td><strong>${h.jumps || 0}</strong></td></tr>
        </table>
      </div>
      <details>
        <summary style="cursor:pointer; margin-bottom: 8px;"><strong>All Statistics (${Object.keys(allStats).length})</strong></summary>
        <table class="players-table" style="font-size:0.85em;">
          <thead><tr><th>Statistic</th><th>Value</th></tr></thead>
          <tbody>
            ${Object.entries(allStats).sort((a,b) => a[0].localeCompare(b[0])).map(([k,v]) =>
              `<tr><td>${escapeHtml(k)}</td><td>${v}</td></tr>`
            ).join('')}
          </tbody>
        </table>
      </details>
    `;
  } catch (error) {
    content.innerHTML = '<p class="empty-message error">No stats available for this player.</p>';
  }
}

function closePlayerStatsModal() {
  document.getElementById('player-stats-modal').classList.remove('active');
}

// Player Inventory
async function viewPlayerInventory(uuid) {
  const modal = document.getElementById('player-inventory-modal');
  const content = document.getElementById('player-inventory-content');
  content.innerHTML = '<p class="empty-message">Loading...</p>';
  modal.classList.add('active');

  try {
    const data = await apiRequest(`/api/servers/${currentServerId}/players/${uuid}/inventory`);
    const gameTypes = { 0: 'Survival', 1: 'Creative', 2: 'Adventure', 3: 'Spectator' };
    const gameType = gameTypes[data.gameType] || 'Unknown';

    function renderItems(items) {
      const list = Array.isArray(items) ? items : (items ? [items] : []);
      const filled = list.filter(i => i && i.id);
      if (!filled.length) return '<p style="color:var(--text-muted);font-style:italic;">Empty</p>';
      return `<ul style="margin:0;padding-left:20px;font-size:0.9em;">${
        filled.map(item => {
          const id = (item.id || '').replace('minecraft:', '');
          const count = item.Count || item.count || 1;
          const slot = item.Slot !== undefined ? `[${item.Slot}] ` : '';
          return `<li>${escapeHtml(slot)}<strong>${escapeHtml(id)}</strong> ×${count}</li>`;
        }).join('')
      }</ul>`;
    }

    content.innerHTML = `
      <div style="margin-bottom:8px;">
        <strong>Health:</strong> ${data.health != null ? Math.round(data.health * 5) + '%' : '—'} &nbsp;
        <strong>Food:</strong> ${data.food != null ? data.food + '/20' : '—'} &nbsp;
        <strong>XP Level:</strong> ${data.xpLevel != null ? data.xpLevel : '—'} &nbsp;
        <strong>Game Mode:</strong> ${escapeHtml(gameType)}
      </div>
      <div style="margin-bottom:12px;"><strong>🗡️ Armor</strong>${renderItems(data.armor)}</div>
      <div style="margin-bottom:12px;"><strong>🤚 Off-hand</strong>${renderItems(data.offhand)}</div>
      <div style="margin-bottom:12px;"><strong>🎒 Inventory</strong>${renderItems(data.inventory)}</div>
      <div><strong>📦 Ender Chest</strong>${renderItems(data.enderChest)}</div>
    `;
  } catch (error) {
    content.innerHTML = '<p class="empty-message error">Could not load inventory data.</p>';
  }
}

function closePlayerInventoryModal() {
  document.getElementById('player-inventory-modal').classList.remove('active');
}

// IP Bans
async function loadBannedIPs() {
  if (!currentServerId) return;
  const tbody = document.getElementById('banned-ips-list');
  if (!tbody) return;
  showTableSkeleton('banned-ips-list', 5, 3);

  try {
    const data = await apiRequest(`/api/servers/${currentServerId}/players/banned-ips`);
    const banned = data.bannedIps || [];
    if (banned.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-message">No banned IPs</td></tr>';
      return;
    }
    tbody.innerHTML = banned.map(entry => {
      const expiresDisplay = (!entry.expires || entry.expires === 'forever')
        ? '<span class="badge badge-danger">Permanent</span>'
        : escapeHtml(entry.expires);
      return `
        <tr>
          <td><strong>${escapeHtml(entry.ip)}</strong></td>
          <td>${escapeHtml(entry.reason || 'No reason')}</td>
          <td>${expiresDisplay}</td>
          <td>${escapeHtml(entry.source || 'Unknown')}</td>
          <td class="actions-cell">
            <button class="btn btn-success btn-small" onclick="unbanIp('${escapeHtml(entry.ip)}')">Unban</button>
          </td>
        </tr>
      `;
    }).join('');
  } catch (error) {
    if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="empty-message error">Failed to load banned IPs</td></tr>';
  }
}

function openBanIpModal() {
  document.getElementById('ban-ip-address').value = '';
  document.getElementById('ban-ip-reason').value = '';
  document.getElementById('ban-ip-expires-type').value = 'forever';
  document.getElementById('ban-ip-expires-date-group').style.display = 'none';
  document.getElementById('ban-ip-modal').classList.add('active');
}

function closeBanIpModal() {
  document.getElementById('ban-ip-modal').classList.remove('active');
}

function toggleBanExpiry() {
  const val = document.getElementById('ban-expires-type').value;
  document.getElementById('ban-expires-date-group').style.display = val === 'date' ? 'block' : 'none';
}

function toggleBanIpExpiry() {
  const val = document.getElementById('ban-ip-expires-type').value;
  document.getElementById('ban-ip-expires-date-group').style.display = val === 'date' ? 'block' : 'none';
}

async function banIp() {
  const ip = document.getElementById('ban-ip-address').value.trim();
  const reason = document.getElementById('ban-ip-reason').value.trim() || 'Banned By Admin';
  const expiresType = document.getElementById('ban-ip-expires-type').value;
  let expires = 'forever';
  if (expiresType === 'date') {
    const dateVal = document.getElementById('ban-ip-expires-date').value;
    if (!dateVal) { showNotification('Please select an expiry date', 'warning'); return; }
    expires = new Date(dateVal).toISOString();
  }
  if (!ip) { showNotification('Please enter an IP address', 'warning'); return; }

  try {
    const result = await apiRequest(`/api/servers/${currentServerId}/players/banned-ips`, {
      method: 'POST',
      body: JSON.stringify({ ip, reason, expires })
    });
    closeBanIpModal();
    showNotification(result.message || `${ip} has been banned`, 'success');
    loadBannedIPs();
  } catch (error) {
    // Error shown by apiRequest
  }
}

async function unbanIp(ip) {
  if (!await confirmAction(`Unban IP ${ip}?`, { title: 'Unban IP', icon: '🌐', okText: 'Unban', okClass: 'btn-success' })) return;
  try {
    await apiRequest(`/api/servers/${currentServerId}/players/banned-ips/${encodeURIComponent(ip)}`, {
      method: 'DELETE'
    });
    showNotification(`${ip} has been unbanned`, 'success');
    loadBannedIPs();
  } catch (error) {
    // Error shown by apiRequest
  }
}

// ==================== Server Messaging ====================

const MC_COLORS = {
  black: '#000000', dark_blue: '#0000AA', dark_green: '#00AA00', dark_aqua: '#00AAAA',
  dark_red: '#AA0000', dark_purple: '#AA00AA', gold: '#FFAA00', gray: '#AAAAAA',
  dark_gray: '#555555', blue: '#5555FF', green: '#55FF55', aqua: '#55FFFF',
  red: '#FF5555', light_purple: '#FF55FF', yellow: '#FFFF55', white: '#FFFFFF'
};

const EVENT_TRIGGER_LABELS = {
  'cron':            'Scheduled',
  'backup_start':    'Backup Starting',
  'backup_complete': 'Backup Complete',
  'server_start':    'Server Started',
  'server_stop':     'Server Stopped',
  'server_crash':    'Server Crashed'
};

const MSG_TYPE_LABELS = {
  'say': '/say', 'msg': '/msg', 'chat': '/tellraw',
  'title': 'Title', 'subtitle': 'Subtitle', 'actionbar': 'Action Bar'
};

function goToMessaging(targetPlayer) {
  switchTab('quickcmds');
  if (targetPlayer) {
    document.getElementById('msg-target').value = targetPlayer;
    document.getElementById('msg-type').value = 'msg';
    onMsgTypeChange();
  }
  const el = document.querySelector('.server-messaging-container');
  if (el) el.scrollIntoView({ behavior: 'smooth' });
}

function openMessagePlayersModal(targetPlayer) {
  goToMessaging(targetPlayer);
}

function onMsgTypeChange() {
  const type = document.getElementById('msg-type').value;
  const targetGroup = document.getElementById('msg-target-group');
  const formatGroup = document.getElementById('msg-formatting-group');
  const targetHelp = document.getElementById('msg-target-help');

  if (type === 'say') {
    targetGroup.style.display = 'none';
    formatGroup.style.display = 'none';
  } else if (type === 'msg') {
    targetGroup.style.display = '';
    formatGroup.style.display = 'none';
    targetHelp.textContent = 'Enter a specific player name (required for /msg)';
  } else {
    targetGroup.style.display = '';
    formatGroup.style.display = '';
    targetHelp.textContent = '@a = all, @p = nearest, or player name';
  }
  updateMsgPreview();
}

function updateMsgPreview() {
  const preview = document.getElementById('msg-preview');
  if (!preview) return;
  const type = document.getElementById('msg-type').value;
  const text = document.getElementById('msg-text').value || 'Your message will appear here';

  if (type === 'say' || type === 'msg') {
    preview.style.color = '#FFFFFF';
    preview.style.fontWeight = 'normal';
    preview.style.fontStyle = 'normal';
    preview.style.textDecoration = 'none';
    if (type === 'say') {
      preview.textContent = `[Server] ${text}`;
    } else {
      const target = document.getElementById('msg-target').value.trim() || 'Player';
      preview.textContent = `You whisper to ${target}: ${text}`;
    }
    return;
  }

  const color = document.getElementById('msg-color').value;
  const bold = document.getElementById('msg-bold').checked;
  const italic = document.getElementById('msg-italic').checked;
  const underlined = document.getElementById('msg-underlined').checked;
  const strikethrough = document.getElementById('msg-strikethrough').checked;
  const obfuscated = document.getElementById('msg-obfuscated').checked;

  preview.style.color = MC_COLORS[color] || '#FFFFFF';
  preview.style.fontWeight = bold ? 'bold' : 'normal';
  preview.style.fontStyle = italic ? 'italic' : 'normal';

  let deco = [];
  if (underlined) deco.push('underline');
  if (strikethrough) deco.push('line-through');
  preview.style.textDecoration = deco.length ? deco.join(' ') : 'none';

  if (obfuscated) {
    preview.textContent = text.replace(/./g, '█');
  } else {
    preview.textContent = text;
  }
}

async function sendPlayerMessage() {
  const type = document.getElementById('msg-type').value;
  const target = document.getElementById('msg-target').value.trim();
  const message = document.getElementById('msg-text').value.trim();

  if (!message) { showNotification('Please enter a message', 'warning'); return; }
  if (type !== 'say' && !target) { showNotification('Please enter a target', 'warning'); return; }
  if (type === 'msg' && (!target || target === '@a')) {
    showNotification('/msg requires a specific player name', 'warning');
    return;
  }

  const body = { type, message, target };
  if (type !== 'say' && type !== 'msg') {
    body.color = document.getElementById('msg-color').value;
    body.bold = document.getElementById('msg-bold').checked;
    body.italic = document.getElementById('msg-italic').checked;
    body.underlined = document.getElementById('msg-underlined').checked;
    body.strikethrough = document.getElementById('msg-strikethrough').checked;
    body.obfuscated = document.getElementById('msg-obfuscated').checked;
  }

  try {
    const result = await apiRequest(`/api/servers/${currentServerId}/players/message`, {
      method: 'POST',
      body: JSON.stringify(body)
    });
    showNotification(result.message || 'Message sent', 'success');
  } catch (error) {
    // Error shown by apiRequest
  }
}

// ── Scheduled / Event Messages ──

async function loadScheduledMessages() {
  if (!currentServerId) return;
  try {
    const data = await apiRequest(`/api/servers/${currentServerId}/messages`);
    renderScheduledMessages(data.messages || []);
  } catch (err) {
    console.error('Failed to load scheduled messages:', err);
  }
}

function renderScheduledMessages(messages) {
  const tbody = document.getElementById('scheduled-messages-list');
  if (!tbody) return;
  if (messages.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-message">No scheduled messages configured.</td></tr>';
    return;
  }
  tbody.innerHTML = messages.map(m => {
    const statusDot = m.enabled ? '🟢' : '⚫';
    const triggerLabel = EVENT_TRIGGER_LABELS[m.trigger] || m.trigger;
    const cronInfo = m.trigger === 'cron' && m.cronExpr ? ` (${escapeHtml(m.cronExpr)})` : '';
    const typeLabel = MSG_TYPE_LABELS[m.msgType] || m.msgType;
    const msgPreview = escapeHtml(m.message.length > 40 ? m.message.substring(0, 40) + '...' : m.message);
    return `<tr>
      <td>${statusDot}</td>
      <td>${escapeHtml(m.name)}</td>
      <td>${escapeHtml(triggerLabel)}${cronInfo}</td>
      <td>${escapeHtml(typeLabel)}</td>
      <td title="${escapeHtml(m.message)}">${msgPreview}</td>
      <td>${m.runCount}</td>
      <td class="actions-cell">
        <button class="btn btn-small" onclick="testScheduledMessage('${m.id}')">Test</button>
        <button class="btn btn-small" onclick="editScheduledMessage('${m.id}')">Edit</button>
        <button class="btn btn-small" onclick="toggleScheduledMessage('${m.id}', ${m.enabled ? 'false' : 'true'})">${m.enabled ? 'Disable' : 'Enable'}</button>
        <button class="btn btn-danger btn-small" onclick="deleteScheduledMessage('${m.id}')">Delete</button>
      </td>
    </tr>`;
  }).join('');
}

function openScheduledMsgModal(msg) {
  const isEdit = !!msg;
  document.getElementById('scheduled-msg-modal-title').textContent = isEdit ? '✏️ Edit Scheduled Message' : '📢 Add Scheduled Message';
  document.getElementById('sched-msg-id').value = isEdit ? msg.id : '';
  document.getElementById('sched-msg-name').value = isEdit ? msg.name : '';
  document.getElementById('sched-msg-trigger').value = isEdit ? msg.trigger : 'cron';
  document.getElementById('sched-msg-cron').value = isEdit && msg.cronExpr ? msg.cronExpr : '0 * * * *';
  document.getElementById('sched-msg-type').value = isEdit ? msg.msgType : 'say';
  document.getElementById('sched-msg-target').value = isEdit ? msg.target : '@a';
  document.getElementById('sched-msg-text').value = isEdit ? msg.message : '';
  document.getElementById('sched-msg-color').value = isEdit ? msg.color : 'white';
  document.getElementById('sched-msg-bold').checked = isEdit ? msg.bold : false;
  document.getElementById('sched-msg-italic').checked = isEdit ? msg.italic : false;
  document.getElementById('sched-msg-underlined').checked = isEdit ? msg.underlined : false;
  document.getElementById('sched-msg-strikethrough').checked = isEdit ? msg.strikethrough : false;
  document.getElementById('sched-msg-obfuscated').checked = isEdit ? msg.obfuscated : false;
  document.getElementById('sched-msg-enabled').checked = isEdit ? msg.enabled : true;
  onSchedTriggerChange();
  onSchedMsgTypeChange();
  document.getElementById('scheduled-msg-modal').classList.add('active');
}

function closeScheduledMsgModal() {
  document.getElementById('scheduled-msg-modal').classList.remove('active');
}

function onSchedTriggerChange() {
  const trigger = document.getElementById('sched-msg-trigger').value;
  document.getElementById('sched-msg-cron-group').style.display = trigger === 'cron' ? '' : 'none';
}

function onSchedMsgTypeChange() {
  const type = document.getElementById('sched-msg-type').value;
  const targetGroup = document.getElementById('sched-msg-target-group');
  const formatGroup = document.getElementById('sched-msg-formatting-group');
  if (type === 'say') {
    targetGroup.style.display = 'none';
    formatGroup.style.display = 'none';
  } else if (type === 'msg') {
    targetGroup.style.display = '';
    formatGroup.style.display = 'none';
  } else {
    targetGroup.style.display = '';
    formatGroup.style.display = '';
  }
}

async function saveScheduledMessage() {
  const msgId = document.getElementById('sched-msg-id').value;
  const name = document.getElementById('sched-msg-name').value.trim();
  const trigger = document.getElementById('sched-msg-trigger').value;
  const msgType = document.getElementById('sched-msg-type').value;
  const message = document.getElementById('sched-msg-text').value.trim();

  if (!name) { showNotification('Name is required', 'warning'); return; }
  if (!message) { showNotification('Message is required', 'warning'); return; }
  if (trigger === 'cron' && !document.getElementById('sched-msg-cron').value.trim()) {
    showNotification('Cron expression is required', 'warning'); return;
  }

  const body = {
    name, trigger, message, msgType,
    cronExpr: document.getElementById('sched-msg-cron').value.trim(),
    target: document.getElementById('sched-msg-target').value.trim() || '@a',
    color: document.getElementById('sched-msg-color').value,
    bold: document.getElementById('sched-msg-bold').checked,
    italic: document.getElementById('sched-msg-italic').checked,
    underlined: document.getElementById('sched-msg-underlined').checked,
    strikethrough: document.getElementById('sched-msg-strikethrough').checked,
    obfuscated: document.getElementById('sched-msg-obfuscated').checked,
    enabled: document.getElementById('sched-msg-enabled').checked,
  };

  try {
    if (msgId) {
      await apiRequest(`/api/servers/${currentServerId}/messages/${msgId}`, {
        method: 'PUT', body: JSON.stringify(body)
      });
    } else {
      await apiRequest(`/api/servers/${currentServerId}/messages`, {
        method: 'POST', body: JSON.stringify(body)
      });
    }
    closeScheduledMsgModal();
    loadScheduledMessages();
    showNotification(msgId ? 'Message updated' : 'Message created', 'success');
  } catch (error) {
    // Error shown by apiRequest
  }
}

async function editScheduledMessage(msgId) {
  try {
    const data = await apiRequest(`/api/servers/${currentServerId}/messages`);
    const msg = (data.messages || []).find(m => m.id === msgId);
    if (msg) openScheduledMsgModal(msg);
  } catch (error) {
    // Error shown by apiRequest
  }
}

async function toggleScheduledMessage(msgId, enable) {
  try {
    await apiRequest(`/api/servers/${currentServerId}/messages/${msgId}`, {
      method: 'PUT', body: JSON.stringify({ enabled: enable === 'true' || enable === true })
    });
    loadScheduledMessages();
    showNotification(enable === 'true' || enable === true ? 'Message enabled' : 'Message disabled', 'success');
  } catch (error) {
    // Error shown by apiRequest
  }
}

async function deleteScheduledMessage(msgId) {
  if (!await confirmAction('Delete this scheduled message?', { title: 'Delete Message', icon: '📢', okText: 'Delete' })) return;
  try {
    await apiRequest(`/api/servers/${currentServerId}/messages/${msgId}`, { method: 'DELETE' });
    loadScheduledMessages();
    showNotification('Message deleted', 'success');
  } catch (error) {
    // Error shown by apiRequest
  }
}

async function testScheduledMessage(msgId) {
  try {
    const data = await apiRequest(`/api/servers/${currentServerId}/messages`);
    const msg = (data.messages || []).find(m => m.id === msgId);
    if (!msg) return;
    await apiRequest(`/api/servers/${currentServerId}/messages/test`, {
      method: 'POST',
      body: JSON.stringify({
        msgType: msg.msgType, target: msg.target, message: msg.message,
        color: msg.color, bold: msg.bold, italic: msg.italic,
        underlined: msg.underlined, strikethrough: msg.strikethrough, obfuscated: msg.obfuscated
      })
    });
    showNotification('Test message sent', 'success');
  } catch (error) {
    // Error shown by apiRequest
  }
}

// Player NBT Editor
async function openPlayerNbtEditor(uuid, path) {
  if (path) {
    try {
      await openNbtEditor(path);
      return;
    } catch (e) {
      // fall through to legacy scan below
    }
  }

  // Legacy fallback: scan known world folder / layout combinations
  // Legacy (<= 1.21.x): world/playerdata/<uuid>.dat
  // 26.1+:              world/players/data/<uuid>.dat
  const worldFolders = ['world', 'world_nether', 'world_the_end'];
  const layouts = [
    (world) => `${world}/players/data/${uuid}.dat`,
    (world) => `${world}/playerdata/${uuid}.dat`,
  ];

  for (const world of worldFolders) {
    for (const buildPath of layouts) {
      try {
        await openNbtEditor(buildPath(world));
        return;
      } catch (e) {
        // Try next
      }
    }
  }
  
  showNotification('Could not find player data file', 'error');
}

// ==================== Drag & Drop Upload ====================
// Generic drop-zone wiring: highlights `zoneEl` while a file is dragged over it
// and hands the dropped FileList to `onFilesDropped`. Uses an enter/leave counter
// so hovering over child elements (e.g. table rows) doesn't cause flicker.
function setupDropZone(zoneEl, onFilesDropped) {
  if (!zoneEl) return;
  let dragCounter = 0;

  zoneEl.addEventListener('dragenter', (e) => {
    e.preventDefault();
    if (!e.dataTransfer || !e.dataTransfer.types.includes('Files')) return;
    dragCounter++;
    zoneEl.classList.add('drag-active');
  });

  zoneEl.addEventListener('dragover', (e) => {
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
  });

  zoneEl.addEventListener('dragleave', (e) => {
    e.preventDefault();
    dragCounter = Math.max(0, dragCounter - 1);
    if (dragCounter === 0) zoneEl.classList.remove('drag-active');
  });

  zoneEl.addEventListener('drop', (e) => {
    e.preventDefault();
    dragCounter = 0;
    zoneEl.classList.remove('drag-active');
    const files = e.dataTransfer ? e.dataTransfer.files : null;
    if (files && files.length > 0) onFilesDropped(files);
  });
}

// ==================== Event Listeners ====================
// Note: Utility functions (formatBytes, escapeHtml) are in utils.js

document.addEventListener('DOMContentLoaded', async () => {
  // Fetch CSRF token first for security
  await fetchCSRFToken();
  
  // Check authentication first
  const isAuthenticated = await checkAuth();
  if (!isAuthenticated) return;
  
  // Load branding settings
  loadBranding();
  
  // Connect WebSocket
  connectWebSocket();
  
  // Load servers
  loadServers();
  
  // Refresh servers periodically
  setInterval(loadServers, 10000);
  
  // Add server buttons (with null checks)
  const addServerBtn = document.getElementById('add-server-btn');
  const welcomeAddBtn = document.getElementById('welcome-add-btn');
  if (addServerBtn) addServerBtn.onclick = openAddServerModal;
  if (welcomeAddBtn) welcomeAddBtn.onclick = openAddServerModal;
  
  // Server sidebar search
  const serverSearch = document.getElementById('server-search');
  if (serverSearch) {
    let _searchDebounce;
    serverSearch.addEventListener('input', () => {
      clearTimeout(_searchDebounce);
      _searchDebounce = setTimeout(renderServerList, 150);
    });
  }
  
  // Server forms
  const unifiedForm = document.getElementById('unified-server-form');
  const manualForm = document.getElementById('manual-server-form');
  if (unifiedForm) unifiedForm.onsubmit = submitUnifiedForm;
  if (manualForm) manualForm.onsubmit = saveServer;
  
  // Custom JAR upload toggle
  const uploadJarToggle = document.getElementById('u-upload-jar');
  if (uploadJarToggle) uploadJarToggle.onchange = toggleUnifiedCustomJar;
  
  // Server actions
  const startBtn = document.getElementById('start-btn');
  const restartBtn = document.getElementById('restart-btn');
  const stopBtn = document.getElementById('stop-btn');
  const killBtn = document.getElementById('kill-btn');
  const editBtn = document.getElementById('edit-server-btn');
  const deleteBtn = document.getElementById('delete-server-btn');
  if (startBtn) startBtn.onclick = startServer;
  if (restartBtn) restartBtn.onclick = restartServer;
  if (stopBtn) stopBtn.onclick = stopServer;
  if (killBtn) killBtn.onclick = killServer;
  if (editBtn) editBtn.onclick = openEditServerModal;
  if (deleteBtn) deleteBtn.onclick = deleteServer;
  
  // Tab buttons
  document.querySelectorAll('.tab-button').forEach(btn => {
    btn.onclick = () => switchTab(btn.dataset.tab);
  });
  
  // Terminal input
  const terminalInput = document.getElementById('terminal-input');
  if (terminalInput) {
    terminalInput.onkeypress = (e) => {
      if (e.key === 'Enter') {
        sendCommand(e.target.value);
        e.target.value = '';
      }
    };
  }
  
  const sendBtn = document.getElementById('send-btn');
  if (sendBtn) {
    sendBtn.onclick = () => {
      const input = document.getElementById('terminal-input');
      if (input) {
        sendCommand(input.value);
        input.value = '';
      }
    };
  }
  
  // Logs controls
  const refreshLogsBtn = document.getElementById('refresh-logs-btn');
  const clearLogsBtn = document.getElementById('clear-logs-view-btn');
  if (refreshLogsBtn) refreshLogsBtn.onclick = loadLogs;
  if (clearLogsBtn) clearLogsBtn.onclick = clearLogsView;
  
  // File explorer controls
  const newFileBtn = document.getElementById('new-file-btn');
  const newFolderBtn = document.getElementById('new-folder-btn');
  const refreshFilesBtn = document.getElementById('refresh-files-btn');
  const fileUpload = document.getElementById('file-upload');
  
  if (newFileBtn) newFileBtn.onclick = createNewFile;
  if (newFolderBtn) newFolderBtn.onclick = createNewFolder;
  if (refreshFilesBtn) refreshFilesBtn.onclick = () => loadFiles(currentPath);
  if (fileUpload) {
    fileUpload.onchange = (e) => {
      if (e.target.files.length > 0) {
        uploadFile(e.target.files[0]);
        e.target.value = '';
      }
    };
  }

  setupDropZone(document.querySelector('.file-explorer'), async (files) => {
    for (const file of files) {
      await uploadFile(file);
    }
  });

  // Mods controls
  const refreshModsBtn = document.getElementById('refresh-mods-btn');
  const modUpload = document.getElementById('mod-upload');
  
  if (refreshModsBtn) refreshModsBtn.onclick = loadMods;
  if (modUpload) {
    modUpload.onchange = async (e) => {
      if (e.target.files.length > 0) {
        // Ask user which folder to upload to
        const choice = await showModUploadDialog();
        if (choice) {
          for (const file of e.target.files) {
            await uploadMod(file, choice);
          }
        }
        e.target.value = '';
      }
    };
  }

  // Dropping directly onto the Plugins or Mods listing uploads straight to that
  // folder, skipping the folder-choice dialog since the drop target already says which.
  const pluginsListEl = document.getElementById('plugins-list');
  const modsListEl = document.getElementById('mods-list');
  setupDropZone(pluginsListEl ? pluginsListEl.closest('.mods-section') : null, async (files) => {
    for (const file of files) {
      await uploadMod(file, 'plugins');
    }
  });
  setupDropZone(modsListEl ? modsListEl.closest('.mods-section') : null, async (files) => {
    for (const file of files) {
      await uploadMod(file, 'mods');
    }
  });

  // File editor
  const saveFileBtn = document.getElementById('save-file-btn');
  if (saveFileBtn) saveFileBtn.onclick = saveFile;
  
  // Backup controls
  const createBackupBtn = document.getElementById('create-backup-btn');
  const scheduleBackupBtn = document.getElementById('schedule-backup-btn');
  const refreshBackupsBtn = document.getElementById('refresh-backups-btn');
  
  if (createBackupBtn) createBackupBtn.onclick = openCreateBackupModal;
  if (scheduleBackupBtn) scheduleBackupBtn.onclick = openScheduleModal;
  if (refreshBackupsBtn) refreshBackupsBtn.onclick = loadBackups;

  setupDropZone(document.querySelector('.backup-list'), async (files) => {
    for (const file of files) {
      await importBackupFile(file);
    }
  });

  // Task controls
  const createTaskBtn = document.getElementById('create-task-btn');
  const refreshTasksBtn = document.getElementById('refresh-tasks-btn');
  
  if (createTaskBtn) createTaskBtn.onclick = openCreateTaskModal;
  if (refreshTasksBtn) refreshTasksBtn.onclick = loadTasks;
  
  // Close modals on background click
  const serverModal = document.getElementById('server-modal');
  if (serverModal) {
    serverModal.onclick = (e) => {
      if (e.target.id === 'server-modal') closeServerModal();
    };
  }
  
  const fileEditorModal = document.getElementById('file-editor-modal');
  if (fileEditorModal) {
    fileEditorModal.onclick = (e) => {
      if (e.target.id === 'file-editor-modal') closeFileEditor();
    };
  }
  
  const scheduleModal = document.getElementById('schedule-modal');
  if (scheduleModal) {
    scheduleModal.onclick = (e) => {
      if (e.target.id === 'schedule-modal') closeScheduleModal();
    };
  }
  
  const taskModal = document.getElementById('task-modal');
  if (taskModal) {
    taskModal.onclick = (e) => {
      if (e.target.id === 'task-modal') closeTaskModal();
    };
  }

  const schedMsgModal = document.getElementById('scheduled-msg-modal');
  if (schedMsgModal) {
    schedMsgModal.onclick = (e) => {
      if (e.target.id === 'scheduled-msg-modal') closeScheduledMsgModal();
    };
  }

  // Modrinth modal close on backdrop + Enter-to-search
  const modrinthModal = document.getElementById('modrinth-modal');
  if (modrinthModal) {
    modrinthModal.onclick = (e) => {
      if (e.target.id === 'modrinth-modal') closeModrinthSearch();
    };
  }
  const modrinthVersionModal = document.getElementById('modrinth-version-modal');
  if (modrinthVersionModal) {
    modrinthVersionModal.onclick = (e) => {
      if (e.target.id === 'modrinth-version-modal') closeModrinthVersionModal();
    };
  }
  const modrinthQuery = document.getElementById('modrinth-query');
  if (modrinthQuery) {
    modrinthQuery.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') doModrinthSearch();
    });
  }
});

// ==================== Properties Management ====================

let currentProperties = {};

async function loadProperties() {
  if (!currentServerId) return;
  
  const editor = document.getElementById('properties-editor');
  const loading = document.getElementById('properties-loading');
  const empty = document.getElementById('properties-empty');
  
  loading.style.display = 'block';
  editor.innerHTML = '';
  empty.style.display = 'none';
  
  try {
    const data = await apiRequest(`/api/servers/${currentServerId}/properties`);
    
    if (data.properties && Object.keys(data.properties).length > 0) {
      currentProperties = data.properties;
      renderPropertiesEditor(data.properties);
      loading.style.display = 'none';
      editor.style.display = 'block';
    } else {
      loading.style.display = 'none';
      empty.style.display = 'flex';
    }
  } catch (error) {
    console.error('Failed to load properties:', error);
    loading.style.display = 'none';
    empty.style.display = 'flex';
  }
}

function renderPropertiesEditor(properties) {
  const editor = document.getElementById('properties-editor');
  editor.innerHTML = '';
  
  // Group properties by category for better organization
  const groups = {
    'Server Settings': ['server-name', 'server-port', 'server-ip', 'max-players', 'white-list', 'allow-list', 'enforce-whitelist', 'online-mode', 'motd'],
    'World Settings': ['level-name', 'level-type', 'level-seed', 'generator-settings', 'generate-structures', 'allow-nether', 'allow-flight', 'max-world-size', 'view-distance', 'simulation-distance'],
    'Gameplay': ['gamemode', 'difficulty', 'hardcore', 'pvp', 'spawn-protection', 'spawn-npcs', 'spawn-animals', 'spawn-monsters', 'max-tick-time'],
    'Performance': ['max-threads', 'rate-limit', 'network-compression-threshold', 'enable-jmx-monitoring', 'sync-chunk-writes'],
    'Advanced': []
  };
  
  // Create a set of all grouped properties
  const groupedProps = new Set();
  Object.values(groups).forEach(group => group.forEach(prop => groupedProps.add(prop)));
  
  // Add ungrouped properties to Advanced
  Object.keys(properties).forEach(key => {
    if (!groupedProps.has(key)) {
      groups['Advanced'].push(key);
    }
  });
  
  // Render each group
  Object.entries(groups).forEach(([groupName, propKeys]) => {
    const groupProps = propKeys.filter(key => properties.hasOwnProperty(key));
    if (groupProps.length === 0 && groupName !== 'Advanced') return;
    
    const groupDiv = document.createElement('div');
    groupDiv.className = 'property-group';
    
    const groupTitle = document.createElement('h3');
    groupTitle.textContent = groupName;
    groupDiv.appendChild(groupTitle);
    
    groupProps.forEach(key => {
      const value = properties[key];
      const propertyDiv = document.createElement('div');
      propertyDiv.className = 'property-item';
      
      const label = document.createElement('label');
      label.className = 'property-label';
      label.htmlFor = `prop-${key}`;
      
      const nameSpan = document.createElement('span');
      nameSpan.className = 'property-name';
      nameSpan.textContent = key;
      label.appendChild(nameSpan);
      
      // Get property metadata
      const metadata = getPropertyMetadata(key);
      
      // Add description if available
      if (metadata.description) {
        const descSpan = document.createElement('span');
        descSpan.className = 'property-description';
        descSpan.textContent = metadata.description;
        label.appendChild(descSpan);
      }
      
      // Add type and default info
      if (metadata.type || metadata.default) {
        const typeSpan = document.createElement('span');
        typeSpan.className = 'property-type-info';
        let typeText = '';
        if (metadata.type) {
          if (metadata.type === 'integer' && metadata.allowedValues) {
            typeText = `${metadata.type} [${metadata.allowedValues}]`;
          } else if (Array.isArray(metadata.allowedValues)) {
            typeText = `${metadata.type} (${metadata.allowedValues.join(', ')})`;
          } else {
            typeText = metadata.type;
          }
        }
        if (metadata.default) {
          typeText += typeText ? ` • default: ${metadata.default}` : `default: ${metadata.default}`;
        }
        typeSpan.textContent = typeText;
        label.appendChild(typeSpan);
      }
      
      propertyDiv.appendChild(label);
      
      // Create container for the value/input
      const valueContainer = document.createElement('div');
      valueContainer.className = 'property-value-container';
      
      // Determine input based on metadata type
      if (metadata.type === 'boolean' || (value === 'true' || value === 'false')) {
        // Create toggle switch container
        const toggleLabel = document.createElement('label');
        toggleLabel.className = 'toggle-switch';
        
        const input = document.createElement('input');
        input.type = 'checkbox';
        input.id = `prop-${key}`;
        input.checked = value === 'true';
        input.dataset.key = key;
        
        const slider = document.createElement('span');
        slider.className = 'toggle-slider';
        
        toggleLabel.appendChild(input);
        toggleLabel.appendChild(slider);
        valueContainer.appendChild(toggleLabel);
      } else if (Array.isArray(metadata.allowedValues) && metadata.allowedValues.length <= 10) {
        // Use select dropdown for properties with limited choices
        const select = document.createElement('select');
        select.id = `prop-${key}`;
        select.className = 'property-select';
        select.dataset.key = key;
        
        metadata.allowedValues.forEach(option => {
          const optionElement = document.createElement('option');
          optionElement.value = option;
          optionElement.textContent = option;
          if (value === option) {
            optionElement.selected = true;
          }
          select.appendChild(optionElement);
        });
        
        valueContainer.appendChild(select);
      } else if (metadata.type === 'integer' || (!isNaN(value) && value !== '')) {
        const input = document.createElement('input');
        input.type = 'number';
        input.id = `prop-${key}`;
        input.className = 'property-input';
        input.value = value;
        input.dataset.key = key;
        
        // Set min/max if available in metadata
        if (metadata.allowedValues && typeof metadata.allowedValues === 'string') {
          const range = metadata.allowedValues.match(/(\d+)-(\d+)/);
          if (range) {
            input.min = range[1];
            input.max = range[2];
          }
        }
        
        valueContainer.appendChild(input);
      } else {
        // String input - use textarea for longer fields
        const isLongField = metadata.maxLength && metadata.maxLength > 50;
        
        if (isLongField) {
          const textarea = document.createElement('textarea');
          textarea.id = `prop-${key}`;
          textarea.className = 'property-textarea';
          textarea.value = value;
          textarea.dataset.key = key;
          textarea.rows = 2;
          if (metadata.maxLength) {
            textarea.maxLength = metadata.maxLength;
          }
          valueContainer.appendChild(textarea);
        } else {
          const input = document.createElement('input');
          input.type = 'text';
          input.id = `prop-${key}`;
          input.className = 'property-input';
          input.value = value;
          input.dataset.key = key;
          if (metadata.maxLength) {
            input.maxLength = metadata.maxLength;
          }
          valueContainer.appendChild(input);
        }
      }
      
      propertyDiv.appendChild(valueContainer);
      groupDiv.appendChild(propertyDiv);
    });
    
    editor.appendChild(groupDiv);
  });
}

function getPropertyMetadata(key) {
  const metadata = {
    'accepts-transfers': {
      type: 'boolean',
      default: 'false',
      description: 'Whether to accept incoming transfers via a transfer packet',
      allowedValues: ['true', 'false']
    },
    'allow-list': {
      type: 'boolean',
      default: 'false',
      description: 'Bedrock: only players listed in allowlist.json can join',
      allowedValues: ['true', 'false']
    },
    'allow-flight': {
      type: 'boolean',
      default: 'false',
      description: 'Allow players to fly in Survival mode. Enabling may make griefing easier',
      allowedValues: ['true', 'false']
    },
    'allow-nether': {
      type: 'boolean',
      default: 'true',
      description: 'Allow players to travel to the Nether dimension',
      allowedValues: ['true', 'false']
    },
    'broadcast-console-to-ops': {
      type: 'boolean',
      default: 'true',
      description: 'Send console command outputs to all online operators',
      allowedValues: ['true', 'false']
    },
    'broadcast-rcon-to-ops': {
      type: 'boolean',
      default: 'true',
      description: 'Send rcon console command outputs to all online operators',
      allowedValues: ['true', 'false']
    },
    'difficulty': {
      type: 'string',
      default: 'easy',
      description: 'Difficulty level of the server',
      allowedValues: ['peaceful', 'easy', 'normal', 'hard']
    },
    'enable-command-block': {
      type: 'boolean',
      default: 'false',
      description: 'Enable command blocks',
      allowedValues: ['true', 'false']
    },
    'enable-jmx-monitoring': {
      type: 'boolean',
      default: 'false',
      description: 'Expose MBean with server tick times in milliseconds',
      allowedValues: ['true', 'false']
    },
    'enable-query': {
      type: 'boolean',
      default: 'false',
      description: 'Enable GameSpy4 protocol server listener for server information',
      allowedValues: ['true', 'false']
    },
    'enable-rcon': {
      type: 'boolean',
      default: 'false',
      description: 'Enable remote access to the server console',
      allowedValues: ['true', 'false']
    },
    'enable-status': {
      type: 'boolean',
      default: 'true',
      description: 'Makes the server appear as "online" on the server list',
      allowedValues: ['true', 'false']
    },
    'enforce-secure-profile': {
      type: 'boolean',
      default: 'true',
      description: 'Only allow players with Mojang-signed public keys to join',
      allowedValues: ['true', 'false']
    },
    'enforce-whitelist': {
      type: 'boolean',
      default: 'false',
      description: 'Kick non-whitelisted players when whitelist is reloaded',
      allowedValues: ['true', 'false']
    },
    'entity-broadcast-range-percentage': {
      type: 'integer',
      default: '100',
      description: 'Controls how close entities need to be before being sent to clients (as percentage)',
      allowedValues: '10-1000'
    },
    'force-gamemode': {
      type: 'boolean',
      default: 'false',
      description: 'Force players to join in the default game mode',
      allowedValues: ['true', 'false']
    },
    'function-permission-level': {
      type: 'integer',
      default: '2',
      description: 'Default permission level for functions',
      allowedValues: '1-4'
    },
    'gamemode': {
      type: 'string',
      default: 'survival',
      description: 'Default game mode for new players',
      allowedValues: ['survival', 'creative', 'adventure', 'spectator']
    },
    'generate-structures': {
      type: 'boolean',
      default: 'true',
      description: 'Generate structures (villages, dungeons, etc.) in new chunks',
      allowedValues: ['true', 'false']
    },
    'generator-settings': {
      type: 'string',
      default: '{}',
      description: 'Settings for world generation customization',
      maxLength: 200
    },
    'hardcore': {
      type: 'boolean',
      default: 'false',
      description: 'Enable hardcore mode (permanent death)',
      allowedValues: ['true', 'false']
    },
    'hide-online-players': {
      type: 'boolean',
      default: 'false',
      description: 'Hide player list in server status requests',
      allowedValues: ['true', 'false']
    },
    'initial-disabled-packs': {
      type: 'string',
      default: '',
      description: 'Comma-separated list of datapacks to disable on world creation',
      maxLength: 200
    },
    'initial-enabled-packs': {
      type: 'string',
      default: 'vanilla',
      description: 'Comma-separated list of datapacks to enable on world creation',
      maxLength: 200
    },
    'level-name': {
      type: 'string',
      default: 'world',
      description: 'Name of the world folder',
      maxLength: 25
    },
    'level-seed': {
      type: 'string',
      default: '',
      description: 'Seed for world generation (leave blank for random)',
      maxLength: 100
    },
    'level-type': {
      type: 'string',
      default: 'normal',
      description: 'World preset for generation',
      allowedValues: ['normal', 'flat', 'large_biomes', 'amplified', 'single_biome_surface']
    },
    'log-ips': {
      type: 'boolean',
      default: 'true',
      description: 'Include client IP addresses in server logs',
      allowedValues: ['true', 'false']
    },
    'max-chained-neighbor-updates': {
      type: 'integer',
      default: '1000000',
      description: 'Limit consecutive neighbor updates before skipping additional ones',
      allowedValues: '1-10000000'
    },
    'max-players': {
      type: 'integer',
      default: '20',
      description: 'Maximum number of players that can join simultaneously',
      allowedValues: '0-2147483647'
    },
    'max-tick-time': {
      type: 'integer',
      default: '60000',
      description: 'Maximum milliseconds per tick before watchdog stops server (-1 to disable)',
      allowedValues: '-1 or 0-9223372036854775807'
    },
    'max-world-size': {
      type: 'integer',
      default: '29999984',
      description: 'Maximum radius of world border in blocks',
      allowedValues: '1-29999984'
    },
    'motd': {
      type: 'string',
      default: 'A Minecraft Server, Powered by MServer',
      description: 'Message shown in server list (59 character limit, supports formatting codes)',
      maxLength: 59
    },
    'network-compression-threshold': {
      type: 'integer',
      default: '256',
      description: 'Packet size threshold for compression in bytes (-1 to disable)',
      allowedValues: '-1 or 0-2147483647'
    },
    'online-mode': {
      type: 'boolean',
      default: 'true',
      description: 'Verify players with Mojang authentication. IMPORTANT: Disable only for offline/LAN servers',
      allowedValues: ['true', 'false']
    },
    'op-permission-level': {
      type: 'integer',
      default: '4',
      description: 'Default permission level for ops',
      allowedValues: '0-4'
    },
    'pause-when-empty-seconds': {
      type: 'integer',
      default: '60',
      description: 'Seconds to wait after no players online before pausing server',
      allowedValues: '0-2147483647'
    },
    'player-idle-timeout': {
      type: 'integer',
      default: '0',
      description: 'Minutes before idle players are kicked (0 to disable)',
      allowedValues: '0-2147483647'
    },
    'prevent-proxy-connections': {
      type: 'boolean',
      default: 'false',
      description: 'Kick players if ISP differs from Mojang authentication server',
      allowedValues: ['true', 'false']
    },
    'pvp': {
      type: 'boolean',
      default: 'true',
      description: 'Enable player versus player combat',
      allowedValues: ['true', 'false']
    },
    'query.port': {
      type: 'integer',
      default: '25565',
      description: 'UDP port for GameSpy4 query listener',
      allowedValues: '1-65535'
    },
    'rate-limit': {
      type: 'integer',
      default: '0',
      description: 'Maximum packets per player before kick (0 to disable)',
      allowedValues: '0-2147483647'
    },
    'rcon.password': {
      type: 'string',
      default: '',
      description: 'Password for RCON (required if RCON is enabled)',
      maxLength: 100
    },
    'rcon.port': {
      type: 'integer',
      default: '25575',
      description: 'TCP port for RCON connections',
      allowedValues: '1-65535'
    },
    'region-file-compression': {
      type: 'string',
      default: 'deflate',
      description: 'Compression algorithm for region files',
      allowedValues: ['deflate', 'lz4', 'none']
    },
    'require-resource-pack': {
      type: 'boolean',
      default: 'false',
      description: 'Disconnect players who decline the resource pack',
      allowedValues: ['true', 'false']
    },
    'resource-pack': {
      type: 'string',
      default: '',
      description: 'URL to optional resource pack (max 250 MiB)',
      maxLength: 300
    },
    'resource-pack-prompt': {
      type: 'string',
      default: '',
      description: 'Custom message for resource pack prompt (chat component syntax)',
      maxLength: 200
    },
    'resource-pack-sha1': {
      type: 'string',
      default: '',
      description: 'SHA-1 hash of resource pack for integrity verification',
      maxLength: 40
    },
    'server-ip': {
      type: 'string',
      default: '',
      description: 'IP address to bind to (leave blank for all interfaces)',
      maxLength: 45
    },
    'server-port': {
      type: 'integer',
      default: '25565',
      description: 'TCP port the server listens on. Must be forwarded if behind NAT',
      allowedValues: '1-65535'
    },
    'server-name': {
      type: 'string',
      default: '',
      description: 'Server name',
      maxLength: 100
    },
    'simulation-distance': {
      type: 'integer',
      default: '10',
      description: 'Maximum distance in chunks for mob spawning and entity updates',
      allowedValues: '3-32'
    },
    'spawn-animals': {
      type: 'boolean',
      default: 'true',
      description: 'Allow animals to spawn',
      allowedValues: ['true', 'false']
    },
    'spawn-monsters': {
      type: 'boolean',
      default: 'true',
      description: 'Allow hostile mobs to spawn',
      allowedValues: ['true', 'false']
    },
    'spawn-npcs': {
      type: 'boolean',
      default: 'true',
      description: 'Allow villagers to spawn',
      allowedValues: ['true', 'false']
    },
    'spawn-protection': {
      type: 'integer',
      default: '16',
      description: 'Radius around spawn where only ops can build (0 to disable)',
      allowedValues: '0-2147483647'
    },
    'sync-chunk-writes': {
      type: 'boolean',
      default: 'true',
      description: 'Enable synchronous chunk writes (prevents data loss after crashes)',
      allowedValues: ['true', 'false']
    },
    'use-native-transport': {
      type: 'boolean',
      default: 'true',
      description: 'Use optimized packet sending/receiving on Linux',
      allowedValues: ['true', 'false']
    },
    'view-distance': {
      type: 'integer',
      default: '10',
      description: 'Server-side view distance in chunks',
      allowedValues: '3-32'
    },
    'white-list': {
      type: 'boolean',
      default: 'false',
      description: 'Enable whitelist (only whitelisted players can join)',
      allowedValues: ['true', 'false']
    }
  };
  
  // Return metadata for known properties, or default to string for unknown
  return metadata[key] || {
    type: 'string',
    default: '',
    description: '',
    maxLength: 100
  };
}

async function saveProperties() {
  if (!currentServerId) return;
  
  const editor = document.getElementById('properties-editor');
  const inputs = editor.querySelectorAll('input[data-key], textarea[data-key], select[data-key]');
  
  const updatedProperties = {};
  inputs.forEach(input => {
    const key = input.dataset.key;
    if (input.type === 'checkbox') {
      updatedProperties[key] = input.checked ? 'true' : 'false';
    } else {
      updatedProperties[key] = input.value;
    }
  });
  
  try {
    await apiRequest(`/api/servers/${currentServerId}/properties`, {
      method: 'POST',
      body: JSON.stringify({ properties: updatedProperties })
    });
    
    showNotification('Properties saved successfully. Restart the server for changes to take effect.', 'success');
    loadProperties(); // Reload to show saved state
  } catch (error) {
    console.error('Failed to save properties:', error);
    showNotification('Failed to save properties: ' + error.message, 'error');
  }
}

function refreshProperties() {
  loadProperties();
}

// Add event listeners for properties buttons
document.addEventListener('DOMContentLoaded', () => {
  const savePropertiesBtn = document.getElementById('save-properties-btn');
  const refreshPropertiesBtn = document.getElementById('refresh-properties-btn');
  
  if (savePropertiesBtn) {
    savePropertiesBtn.addEventListener('click', saveProperties);
  }
  
  if (refreshPropertiesBtn) {
    refreshPropertiesBtn.addEventListener('click', refreshProperties);
  }
});

// ==================== Resource Pack Management ====================

async function loadResourcePack() {
  if (!currentServerId) return;
  
  const statusDiv = document.getElementById('resourcepack-status');
  const uploadSection = document.getElementById('resourcepack-upload-section');
  const detailsSection = document.getElementById('resourcepack-details');
  
  statusDiv.innerHTML = '<div class="loading">Loading resource pack information...</div>';
  uploadSection.style.display = 'block';
  detailsSection.style.display = 'none';
  
  try {
    const data = await apiRequest(`/api/servers/${currentServerId}/resourcepack`);
    
    if (data.exists) {
      // Show resource pack details
      statusDiv.innerHTML = '<div class="success-message">✓ Resource pack is configured for this server</div>';
      uploadSection.style.display = 'none';
      detailsSection.style.display = 'block';
      
      document.getElementById('rp-filename').textContent = data.filename;
      document.getElementById('rp-size').textContent = formatBytes(data.size);
      document.getElementById('rp-uploaded').textContent = new Date(data.uploaded).toLocaleString();
      document.getElementById('rp-sha1').textContent = data.sha1;
      
      const urlLink = document.getElementById('rp-url');
      if (data.url) {
        urlLink.href = data.url;
        urlLink.textContent = data.url;
      } else {
        urlLink.href = '#';
        urlLink.textContent = 'No base URL configured';
      }
    } else {
      // No resource pack uploaded
      statusDiv.innerHTML = '<div class="info-message">ℹ No resource pack uploaded yet</div>';
      uploadSection.style.display = 'block';
      detailsSection.style.display = 'none';
    }
  } catch (error) {
    statusDiv.innerHTML = `<div class="error-message">Error loading resource pack: ${escapeHtml(error.message)}</div>`;
  }
}

async function uploadResourcePack(file) {
  if (!currentServerId) return;
  
  const statusDiv = document.getElementById('resourcepack-status');
  
  // Validate file
  if (!file.name.toLowerCase().endsWith('.zip')) {
    showNotification('File must be a .zip file', 'error');
    return;
  }
  
  // Check file size (100MB)
  const maxSize = 100 * 1024 * 1024;
  if (file.size > maxSize) {
    showNotification(`File size exceeds 100MB limit (${(file.size / (1024*1024)).toFixed(2)}MB)`, 'error');
    return;
  }
  
  statusDiv.innerHTML = '<div class="loading">Uploading resource pack...</div>';
  
  try {
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await fetch(`/api/servers/${currentServerId}/resourcepack/upload`, {
      method: 'POST',
      headers: window.csrfToken ? { 'X-CSRF-Token': window.csrfToken } : {},
      body: formData
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Upload failed');
    }
    
    const data = await response.json();
    
    showNotification('Resource pack uploaded successfully!', 'success');
    
    if (data.propertiesUpdated) {
      showNotification('server.properties updated with resource pack URL and SHA-1 hash', 'success');
    }
    
    // Reload the resource pack info
    loadResourcePack();
  } catch (error) {
    statusDiv.innerHTML = `<div class="error-message">Upload failed: ${escapeHtml(error.message)}</div>`;
    showNotification('Failed to upload resource pack: ' + error.message, 'error');
  }
}

async function deleteResourcePack() {
  if (!currentServerId) return;
  
  if (!await confirmAction('Are you sure you want to delete this resource pack? This will also remove the resource pack configuration from server.properties.', { title: 'Delete Resource Pack', icon: '📦', okText: 'Delete' })) {
    return;
  }
  
  const statusDiv = document.getElementById('resourcepack-status');
  statusDiv.innerHTML = '<div class="loading">Deleting resource pack...</div>';
  
  try {
    await apiRequest(`/api/servers/${currentServerId}/resourcepack`, {
      method: 'DELETE'
    });
    
    showNotification('Resource pack deleted successfully', 'success');
    loadResourcePack();
  } catch (error) {
    statusDiv.innerHTML = `<div class="error-message">Delete failed: ${escapeHtml(error.message)}</div>`;
    showNotification('Failed to delete resource pack: ' + error.message, 'error');
  }
}

// Add event listeners for resource pack
document.addEventListener('DOMContentLoaded', () => {
  const uploadInput = document.getElementById('resourcepack-upload');
  const replaceBtn = document.getElementById('replace-resourcepack-btn');
  const deleteBtn = document.getElementById('delete-resourcepack-btn');
  
  if (uploadInput) {
    uploadInput.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) {
        uploadResourcePack(file);
      }
      // Reset input so same file can be selected again
      e.target.value = '';
    });
  }
  
  if (replaceBtn) {
    replaceBtn.addEventListener('click', () => {
      uploadInput.click();
    });
  }
  
  if (deleteBtn) {
    deleteBtn.addEventListener('click', deleteResourcePack);
  }

  setupDropZone(document.getElementById('resourcepack-upload-section'), (files) => {
    uploadResourcePack(files[0]);
  });
});

// ==================== Quick Commands ====================

let _cannedCommands = [];   // {cmdName, cmd}
let _autoExec = false;

async function loadCannedCommands() {
  if (!currentServerId) return;
  try {
    const data = await apiRequest(`/api/servers/${currentServerId}/canned-commands`);
    _cannedCommands = data.commands || [];
    _autoExec = !!data.autoExecute;
    const toggle = document.getElementById('quickcmds-autoexec');
    if (toggle) toggle.checked = _autoExec;
    updateAutoExecHint();
    renderCannedCommandsGrid();
    renderCannedCommandsTable();
  } catch (err) {
    console.error('Failed to load canned commands:', err);
  }
}

async function saveCannedCommandsToServer() {
  if (!currentServerId) return;
  try {
    await apiRequest(`/api/servers/${currentServerId}/canned-commands`, {
      method: 'PUT',
      body: JSON.stringify({ autoExecute: _autoExec, commands: _cannedCommands })
    });
  } catch (err) {
    showNotification('Failed to save commands: ' + err.message, 'error');
  }
}

function renderCannedCommandsGrid() {
  const grid = document.getElementById('quickcmds-grid');
  if (!grid) return;
  const serverRunning = grid.dataset.serverRunning === 'true';
  grid.innerHTML = '';
  if (_cannedCommands.length === 0) {
    grid.innerHTML = '<span class="quickcmds-empty">No quick commands configured. Set them up in the Commands tab.</span>';
    return;
  }
  _cannedCommands.forEach((item, idx) => {
    const btn = document.createElement('button');
    btn.className = 'quickcmd-btn';
    btn.title = item.cmd;
    btn.textContent = item.cmdName || item.cmd.substring(0, 25);
    btn.disabled = !serverRunning;
    btn.addEventListener('click', () => triggerCannedCommand(idx));
    grid.appendChild(btn);
  });
}

function renderCannedCommandsTable() {
  const tbody = document.getElementById('quickcmds-list');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (_cannedCommands.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" class="empty-message">No commands yet.</td></tr>';
    return;
  }
  _cannedCommands.forEach((item, idx) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escapeHtml(item.cmdName)}</td>
      <td class="cmd-text">${escapeHtml(item.cmd)}</td>
      <td class="actions-cell">
        <button class="btn btn-small" onclick="openAddCmdModal(${idx})">Edit</button>
        <button class="btn btn-danger btn-small" onclick="deleteCannedCommand(${idx})">Delete</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function triggerCannedCommand(idx) {
  const item = _cannedCommands[idx];
  if (!item) return;
  const input = document.getElementById('terminal-input');
  if (_autoExec) {
    // Auto-send directly
    sendCommand(item.cmd);
  } else {
    // Fill terminal input
    if (input) {
      input.value = item.cmd;
      input.focus();
    }
    // Switch to terminal tab so user can see the filled prompt
    switchTab('terminal');
  }
}

function onAutoExecToggle() {
  const toggle = document.getElementById('quickcmds-autoexec');
  _autoExec = toggle ? toggle.checked : false;
  updateAutoExecHint();
  saveCannedCommandsToServer();
}

function updateAutoExecHint() {
  const hint = document.getElementById('quickcmds-autoexec-hint');
  if (!hint) return;
  hint.textContent = _autoExec
    ? 'On — clicking a button sends the command immediately'
    : 'Off — clicks fill the terminal prompt';
}

function openAddCmdModal(editIdx = -1) {
  document.getElementById('addcmd-index').value = editIdx;
  if (editIdx >= 0 && editIdx < _cannedCommands.length) {
    const item = _cannedCommands[editIdx];
    document.getElementById('addcmd-modal-title').textContent = '✏️ Edit Command';
    document.getElementById('addcmd-name').value = item.cmdName;
    document.getElementById('addcmd-cmd').value = item.cmd;
  } else {
    document.getElementById('addcmd-modal-title').textContent = '➕ Add Command';
    document.getElementById('addcmd-name').value = '';
    document.getElementById('addcmd-cmd').value = '';
  }
  document.getElementById('addcmd-modal').style.display = 'flex';
  document.getElementById('addcmd-name').focus();
}

function closeAddCmdModal() {
  document.getElementById('addcmd-modal').style.display = 'none';
}

async function saveAddCmdModal() {
  const editIdx = parseInt(document.getElementById('addcmd-index').value, 10);
  const rawName = document.getElementById('addcmd-name').value.trim();
  const cmd = document.getElementById('addcmd-cmd').value.trim();

  if (!rawName) { showNotification('Button name is required', 'error'); return; }
  if (!cmd) { showNotification('Command is required', 'error'); return; }

  const cmdName = rawName.substring(0, 25);

  if (editIdx >= 0 && editIdx < _cannedCommands.length) {
    _cannedCommands[editIdx] = { cmdName, cmd };
  } else {
    _cannedCommands.push({ cmdName, cmd });
  }

  closeAddCmdModal();
  renderCannedCommandsGrid();
  renderCannedCommandsTable();
  await saveCannedCommandsToServer();
  showNotification('Command saved', 'success');
}

async function deleteCannedCommand(idx) {
  if (!await confirmAction('Delete this command?', { title: 'Delete Command', icon: '⚡', okText: 'Delete' })) return;
  _cannedCommands.splice(idx, 1);
  renderCannedCommandsGrid();
  renderCannedCommandsTable();
  await saveCannedCommandsToServer();
}

