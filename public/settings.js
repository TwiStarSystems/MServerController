// Settings page JavaScript

// Note: CSRF token management is in utils.js (window.csrfToken and fetchCSRFToken)

let socket = null;
let statsChart = null;
let currentUser = null;

// Global fetch wrapper to handle authentication errors and CSRF
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

  // Redirect to login if authentication fails
  if (response.status === 401) {
    window.location.href = '/login.html';
  }

  return response;
};

document.addEventListener('DOMContentLoaded', async () => {
  // Fetch CSRF token first
  await fetchCSRFToken();
  
  // Set up tab switching FIRST before any async operations
  document.querySelectorAll('.settings-tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab;
      
      document.querySelectorAll('.settings-tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      
      document.querySelectorAll('.settings-section').forEach(s => s.classList.remove('active'));
      document.getElementById(`${tab}-section`).classList.add('active');
      
      // Load users when User Management tab is clicked
      if (tab === 'users') {
        loadUsers();
        loadGroups();
      }
      // Load approvals when Approvals tab is clicked
      if (tab === 'approvals') {
        loadPendingApprovals();
      }
      // Load API manager when API Manager tab is clicked
      if (tab === 'api') {
        loadApiManager();
      }
      // Load app settings when Server Settings tab is clicked
      if (tab === 'appsettings') {
        loadAppSettings();
      }
      // Load external backup settings when that tab is clicked
      if (tab === 'external-backup') {
        loadExternalBackupSettings();
      }
      // Load version info and JAR bucket when Tools tab is clicked
      if (tab === 'tools') {
        loadVersionInfo();
        loadJarBucketTypes();
        loadJarBucketDownloaded();
        refreshJarDownloadQueue();
        initJarLinksPanel();
      }
      // Load host/OS update status when Updates tab is clicked
      if (tab === 'updates') {
        loadOsUpdateStatus();
      }
    });
  });
  
  // Check authentication
  try {
    const response = await fetch('/api/auth/me');
    if (!response.ok) {
      window.location.href = '/login.html';
      return;
    }
    currentUser = await response.json();
    window.currentUser = currentUser;
    const hasPanel = currentUser.permissions && currentUser.permissions.some(p => p === '*' || p.startsWith('panel.'));
    if (!hasPanel) {
      window.location.href = '/';
      return;
    }
    updateUserUI();
    applyTabVisibility();
  } catch (err) {
    console.error('Auth error:', err);
    window.location.href = '/login.html';
    return;
  }
  
  // Load branding for page
  loadPageBranding();
  
  // Initialize Socket.IO for real-time stats
  try {
    socket = io();
    socket.on('stats_update', updateCurrentStats);
  } catch (err) {
    console.error('Socket.IO error:', err);
  }
  
  // Load initial data
  loadCurrentStats();
  loadStatsHistory();
  loadBranding();
  loadTools();
  loadJarBucketTypes();
  loadJarBucketDownloaded();
  refreshJarDownloadQueue();
  initJarLinksPanel();

  // Time range change handler
  document.getElementById('time-range').addEventListener('change', loadStatsHistory);
  
  // Branding form
  document.getElementById('branding-form').addEventListener('submit', saveBranding);
  
  // Live preview for branding
  document.getElementById('branding-site-title').addEventListener('input', updateBrandingPreview);
  document.getElementById('site-icon').addEventListener('change', handleFaviconSelect);
  document.getElementById('footer-addition').addEventListener('input', updateBrandingPreview);
  
  // Favicon upload button
  document.getElementById('upload-favicon-btn').addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('site-icon').click();
  });
  
  // Initialize chart
  initChart();
});

// ==================== User UI Functions ====================

function updateUserUI() {
  const userInfo = document.getElementById('user-info');
  if (userInfo && currentUser) {
    const groupName = currentUser.groupName || 'No Group';
    userInfo.innerHTML = `
      <div class="user-display">
        <span class="user-name">${escapeHtml(currentUser.username)}</span>
        <span class="group-badge">${escapeHtml(groupName)}</span>
      </div>
      <div class="user-actions">
        <button class="btn-icon" onclick="openProfileSettings()" title="Profile Settings">⚙️</button>
        <button class="btn-icon" onclick="logout()" title="Logout">🚪</button>
      </div>
    `;
  }
}

function applyTabVisibility() {
  const tabMap = {
    'stats': 'panel.stats.view',
    'branding': 'panel.settings.manage',
    'users': 'panel.users.view',
    'approvals': 'panel.approvals.manage',
    'api': 'panel.settings.manage',
    'appsettings': 'panel.settings.view',
    'external-backup': 'panel.settings.view',
    'tools': 'panel.tools.manage',
    'updates': 'panel.tools.manage',
  };
  let firstVisible = null;
  document.querySelectorAll('.settings-tab-btn').forEach(btn => {
    const tab = btn.getAttribute('data-tab');
    const perm = tabMap[tab];
    if (perm && !hasPermission(perm)) {
      btn.style.display = 'none';
    } else {
      if (!firstVisible) firstVisible = tab;
    }
  });
  if (firstVisible) {
    document.querySelectorAll('.settings-tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.settings-section').forEach(s => s.classList.remove('active'));
    const activeBtn = document.querySelector(`.settings-tab-btn[data-tab="${firstVisible}"]`);
    const activeSec = document.getElementById(`${firstVisible}-section`);
    if (activeBtn) activeBtn.classList.add('active');
    if (activeSec) activeSec.classList.add('active');
  }
}

async function loadPageBranding() {
  try {
    const response = await fetch('/api/settings/branding');
    if (response.ok) {
      const branding = await response.json();
      
      // Update page title
      const siteTitle = branding.siteTitle || '🎮 MServer';
      document.getElementById('site-title').textContent = siteTitle;
      document.title = `Settings - ${siteTitle.replace(/^🎮\s*/, '')}`;
      
      // Update favicon
      if (branding.siteIcon) {
        let favicon = document.querySelector("link[rel~='icon']");
        if (!favicon) {
          favicon = document.createElement('link');
          favicon.rel = 'icon';
          document.head.appendChild(favicon);
        }
        // siteIcon is now a filename stored on the server
        favicon.href = `/favicons/${branding.siteIcon}`;
      }
    }
  } catch (err) {
    console.error('Failed to load page branding:', err);
  }
}

async function logout() {
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
  } catch (err) {
    console.error('Logout error:', err);
  }
  window.location.href = '/login.html';
}

// ==================== Profile Settings ====================

let currentMFASecret = null;
let currentRecoveryCode = null;

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
    
    // Load notification preferences
    loadNotificationPrefs();
    
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
    
    // Save notification preferences
    await saveNotificationPrefs(true);  // silent — profile save message covers it
    
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
  
  const passwordError = validatePassword(newPassword);
  if (passwordError) {
    showNotification(passwordError, 'error');
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

// ==================== Stats Functions ====================

function initChart() {
  const ctx = document.getElementById('stats-chart').getContext('2d');
  
  statsChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'CPU %',
          data: [],
          borderColor: '#ff6384',
          backgroundColor: 'rgba(255, 99, 132, 0.1)',
          tension: 0.4,
          fill: true
        },
        {
          label: 'Memory %',
          data: [],
          borderColor: '#36a2eb',
          backgroundColor: 'rgba(54, 162, 235, 0.1)',
          tension: 0.4,
          fill: true
        },
        {
          label: 'Disk %',
          data: [],
          borderColor: '#ffce56',
          backgroundColor: 'rgba(255, 206, 86, 0.1)',
          tension: 0.4,
          fill: true
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {
        intersect: false,
        mode: 'index'
      },
      plugins: {
        legend: {
          position: 'top',
          labels: {
            color: '#888',
            usePointStyle: true
          }
        }
      },
      scales: {
        x: {
          grid: {
            color: '#333'
          },
          ticks: {
            color: '#888',
            maxTicksLimit: 12
          }
        },
        y: {
          min: 0,
          max: 100,
          grid: {
            color: '#333'
          },
          ticks: {
            color: '#888',
            callback: value => value + '%'
          }
        }
      }
    }
  });
}

async function loadCurrentStats() {
  try {
    const response = await fetch('/api/stats/current');
    if (response.ok) {
      const stats = await response.json();
      updateCurrentStats(stats);
    }
  } catch (err) {
    console.error('Failed to load current stats:', err);
  }
}

function updateCurrentStats(stats) {
  // CPU
  const cpuPercent = Math.round(stats.cpu || 0);
  document.getElementById('cpu-value').textContent = cpuPercent + '%';
  document.getElementById('cpu-bar').style.width = cpuPercent + '%';
  
  // Memory
  const memPercent = Math.round(stats.memory?.percent || 0);
  const memUsed = formatBytes(stats.memory?.used || 0);
  const memTotal = formatBytes(stats.memory?.total || 0);
  document.getElementById('memory-value').textContent = memPercent + '%';
  document.getElementById('memory-bar').style.width = memPercent + '%';
  document.getElementById('memory-details').textContent = `${memUsed} / ${memTotal}`;
  
  // Disk
  const diskPercent = Math.round(stats.disk?.percent || 0);
  const diskUsed = formatBytes(stats.disk?.used || 0);
  const diskTotal = formatBytes(stats.disk?.total || 0);
  document.getElementById('disk-value').textContent = diskPercent + '%';
  document.getElementById('disk-bar').style.width = diskPercent + '%';
  document.getElementById('disk-details').textContent = `${diskUsed} / ${diskTotal}`;
}

async function loadStatsHistory() {
  const hours = parseInt(document.getElementById('time-range').value);
  
  try {
    const response = await fetch(`/api/stats/history?hours=${hours}`);
    if (response.ok) {
      const data = await response.json();
      updateChart(data.history, hours);
    }
  } catch (err) {
    console.error('Failed to load stats history:', err);
  }
}

function updateChart(history, hours) {
  if (!statsChart || !history || history.length === 0) return;
  
  // Determine how many points to show based on time range
  const maxPoints = hours <= 6 ? 100 : hours <= 24 ? 150 : 200;
  const step = Math.max(1, Math.floor(history.length / maxPoints));
  
  const filteredHistory = history.filter((_, i) => i % step === 0);
  
  // Format labels based on time range
  const labels = filteredHistory.map(s => {
    const date = new Date(s.timestamp);
    if (hours <= 24) {
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } else {
      return date.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + 
             date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
  });
  
  statsChart.data.labels = labels;
  statsChart.data.datasets[0].data = filteredHistory.map(s => s.cpu || 0);
  statsChart.data.datasets[1].data = filteredHistory.map(s => s.memory?.percent || 0);
  statsChart.data.datasets[2].data = filteredHistory.map(s => s.disk?.percent || 0);
  statsChart.update();
}

// ==================== Branding Functions ====================

async function loadBranding() {
  try {
    const response = await fetch('/api/settings/branding');
    if (response.ok) {
      const branding = await response.json();
      
      document.getElementById('branding-site-title').value = branding.siteTitle || '';
      document.getElementById('footer-addition').value = branding.footerAddition || '';
      
      // Handle favicon
      if (branding.siteIcon) {
        // siteIcon is a filename, update the display
        document.getElementById('favicon-filename').textContent = branding.siteIcon;
        const previewContainer = document.getElementById('favicon-preview');
        previewContainer.style.display = 'block';
        document.getElementById('favicon-preview-img').src = `/favicons/${branding.siteIcon}`;
      }
      
      updateBrandingPreview();
    }
  } catch (err) {
    console.error('Failed to load branding:', err);
  }
}

function handleFaviconSelect(e) {
  const file = e.target.files[0];
  
  if (!file) {
    document.getElementById('favicon-filename').textContent = 'No file selected';
    document.getElementById('favicon-preview').style.display = 'none';
    return;
  }
  
  // Validate file type
  const validTypes = ['image/png', 'image/jpeg', 'image/gif', 'image/x-icon'];
  if (!validTypes.includes(file.type)) {
    alert('Invalid file type. Please upload a PNG, JPEG, GIF, or ICO image.');
    e.target.value = '';
    document.getElementById('favicon-filename').textContent = 'No file selected';
    document.getElementById('favicon-preview').style.display = 'none';
    return;
  }
  
  // Update filename display
  document.getElementById('favicon-filename').textContent = file.name;
  
  // Show preview
  const reader = new FileReader();
  reader.onload = (event) => {
    document.getElementById('favicon-preview-img').src = event.target.result;
    document.getElementById('favicon-preview').style.display = 'block';
  };
  reader.readAsDataURL(file);
  
  updateBrandingPreview();
}

function updateBrandingPreview() {
  const title = document.getElementById('branding-site-title').value || 'MServer';
  const footerAddition = document.getElementById('footer-addition').value;
  const faviconFile = document.getElementById('site-icon').files[0];
  
  document.getElementById('preview-title').textContent = title;
  
  const iconEl = document.getElementById('preview-icon');
  if (faviconFile) {
    const reader = new FileReader();
    reader.onload = (event) => {
      iconEl.innerHTML = `<img src="${event.target.result}" alt="icon" onerror="this.parentElement.innerHTML='🎮'" style="max-width: 100%; max-height: 100%;">`;
    };
    reader.readAsDataURL(faviconFile);
  } else {
    // Check if there's an existing favicon from the server
    const existingFaviconSrc = document.getElementById('favicon-preview-img').src;
    if (existingFaviconSrc && document.getElementById('favicon-preview').style.display !== 'none') {
      iconEl.innerHTML = `<img src="${existingFaviconSrc}" alt="icon" onerror="this.parentElement.innerHTML='🎮'" style="max-width: 100%; max-height: 100%;">`;
    } else {
      iconEl.innerHTML = '🎮';
    }
  }
  
  const footerEl = document.getElementById('preview-footer-addition');
  if (footerAddition) {
    footerEl.innerHTML = footerAddition + ' | ';
  } else {
    footerEl.innerHTML = '';
  }
}

async function saveBranding(e) {
  e.preventDefault();
  
  const faviconFile = document.getElementById('site-icon').files[0];
  const siteTitle = document.getElementById('branding-site-title').value;
  const footerAddition = document.getElementById('footer-addition').value;
  
  try {
    const formData = new FormData();
    formData.append('siteTitle', siteTitle);
    formData.append('footerAddition', footerAddition);
    if (faviconFile) {
      formData.append('favicon', faviconFile);
    }
    
    const response = await fetch('/api/settings/branding', {
      method: 'PUT',
      body: formData
    });
    
    if (response.ok) {
      const result = await response.json();
      alert('Branding saved successfully!');
      
      // Reload branding to get the updated favicon filename from server
      await loadBranding();
      
      // Update page title and header
      const displayTitle = siteTitle || '🎮 MServer';
      document.getElementById('site-title').textContent = displayTitle;
      document.title = `Settings - ${displayTitle.replace(/^🎮\s*/, '')}`;
    } else {
      const err = await response.json();
      alert('Failed to save branding: ' + (err.error || 'Unknown error'));
    }
  } catch (err) {
    alert('Failed to save branding: ' + err.message);
  }
}

// ==================== Tools Functions ====================

// ---- Server Backup / Restore ----

async function backupAllServers() {
  const btn = document.getElementById('backup-all-btn');
  const status = document.getElementById('backup-all-status');

  btn.disabled = true;
  btn.textContent = '⏳ Creating archive…';
  status.textContent = '';
  status.className = 'jar-status';

  try {
    const response = await fetch('/api/tools/servers/backup-all', { method: 'POST' });

    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.error || `Server error ${response.status}`);
    }

    // Trigger browser download
    const blob = await response.blob();
    const disposition = response.headers.get('Content-Disposition') || '';
    const match = disposition.match(/filename="([^"]+)"/);
    const filename = match ? match[1] : 'mserver_backup_all.zip';

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    status.textContent = `✅ Archive downloaded: ${filename}`;
    status.classList.add('status-success');
  } catch (err) {
    status.textContent = `❌ Backup failed: ${err.message}`;
    status.classList.add('status-error');
  } finally {
    btn.disabled = false;
    btn.textContent = '📥 Download All Servers';
  }
}

function onRestoreFileSelected(input) {
  const label = document.getElementById('restore-filename');
  const restoreBtn = document.getElementById('restore-all-btn');
  if (input.files && input.files.length > 0) {
    label.textContent = input.files[0].name;
    restoreBtn.disabled = false;
  } else {
    label.textContent = 'No file selected';
    restoreBtn.disabled = true;
  }
}

async function restoreAllServers() {
  const fileInput = document.getElementById('restore-file-input');
  const mode = document.getElementById('restore-mode').value;
  const btn = document.getElementById('restore-all-btn');
  const status = document.getElementById('restore-all-status');

  if (!fileInput.files || fileInput.files.length === 0) {
    alert('Please select a backup ZIP file first.');
    return;
  }

  const warningMsg = mode === 'replace'
    ? 'REPLACE mode will DELETE ALL existing servers before restoring.\n\nAre you absolutely sure? This cannot be undone.'
    : `Merge mode will overwrite servers found in the archive.\n\nContinue?`;

  if (!confirm(warningMsg)) return;

  btn.disabled = true;
  btn.textContent = '⏳ Restoring…';
  status.textContent = '';
  status.className = 'jar-status';

  try {
    const formData = new FormData();
    formData.append('backup', fileInput.files[0]);

    // Use originalFetch so the global wrapper's header injection doesn't
    // interfere with FormData (multipart) boundary — CSRF is still sent via
    // the X-CSRF-Token header added on POST by the wrapper.
    const response = await fetch(`/api/tools/servers/restore-all?mode=${encodeURIComponent(mode)}`, {
      method: 'POST',
      body: formData
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Server error ${response.status}`);

    const serverList = data.serversRestored.length > 0
      ? data.serversRestored.join(', ')
      : 'none';
    status.textContent = `✅ Restored ${data.serversRestored.length} server(s): ${serverList}  (${data.filesRestored} files)`;
    status.classList.add('status-success');

    // Reset file input
    fileInput.value = '';
    document.getElementById('restore-filename').textContent = 'No file selected';
    btn.disabled = true;
    btn.textContent = '🔄 Restore Servers';
  } catch (err) {
    status.textContent = `❌ Restore failed: ${err.message}`;
    status.classList.add('status-error');
    btn.disabled = false;
    btn.textContent = '🔄 Restore Servers';
  }
}

// ---- End Server Backup / Restore ----

async function loadTools() {
  const container = document.getElementById('tools-container');
  
  try {
    const response = await fetch('/api/tools');
    const responseText = await response.text();
    
    // Try to parse as JSON
    let data;
    try {
      data = JSON.parse(responseText);
    } catch (parseErr) {
      throw new Error(`Invalid JSON response: ${responseText.substring(0, 200)}`);
    }
    
    if (!response.ok) {
      throw new Error(`Server returned ${response.status}: ${data.error || response.statusText}`);
    }
    
    if (data.tools && data.tools.length > 0) {
      container.innerHTML = data.tools.map(tool => `
        <div class="tool-item" data-tool="${tool.name}">
          <div class="tool-item-header">
            <div class="tool-info">
              <h4 class="tool-name">📜 ${escapeHtml(tool.filename)}</h4>
              <p class="tool-desc">${escapeHtml(tool.description)}</p>
            </div>
            <div class="tool-header-btns">
              <button class="btn btn-small tool-toggle" onclick="toggleToolExpand('${tool.name}')" title="Expand/Collapse">▼</button>
              <button class="btn btn-small btn-danger" onclick="deleteTool('${tool.name}')" title="Delete Tool">🗑️</button>
            </div>
          </div>
          <div class="tool-details" id="details-${tool.name}" style="display: none;">
            <div class="tool-args-section">
              <label>Arguments (optional):</label>
              <input type="text" class="form-control tool-args-input" id="args-${tool.name}" 
                     placeholder="e.g., --download-latest=10 --quiet" />
              <small class="tool-args-hint">Enter command-line arguments separated by spaces</small>
            </div>
            <div class="tool-actions">
              <button class="btn btn-primary" onclick="runTool('${tool.name}')">▶️ Run Tool</button>
              <span class="tool-status" id="status-${tool.name}"></span>
            </div>
            <div class="tool-output" id="output-${tool.name}"></div>
          </div>
        </div>
      `).join('');
    } else {
      container.innerHTML = `
        <div class="no-tools">
          <h3>No Tools Available</h3>
          <p>Add Python scripts to the <code>./tools</code> folder to see them here.</p>
          <p>Each script should have a comment at the top describing its purpose.</p>
          <p><small>API returned: ${data.tools ? data.tools.length : 0} tools</small></p>
        </div>
      `;
    }
  } catch (err) {
    container.innerHTML = `
      <div class="no-tools">
        <h3>Failed to Load Tools</h3>
        <p>${err.message}</p>
      </div>
    `;
  }
}

function toggleToolExpand(toolName) {
  const details = document.getElementById(`details-${toolName}`);
  const toggle = document.querySelector(`[data-tool="${toolName}"] .tool-toggle`);
  
  if (details.style.display === 'none') {
    details.style.display = 'block';
    toggle.textContent = '▲';
  } else {
    details.style.display = 'none';
    toggle.textContent = '▼';
  }
}

async function uploadTool(input) {
  const file = input.files[0];
  if (!file) return;
  
  const statusDiv = document.getElementById('tool-upload-status');
  
  // Validate file extension
  if (!file.name.toLowerCase().endsWith('.py')) {
    statusDiv.style.display = 'block';
    statusDiv.className = 'upload-status error';
    statusDiv.innerHTML = '❌ Only Python (.py) files are allowed';
    input.value = ''; // Clear the input
    return;
  }
  
  // Show uploading status
  statusDiv.style.display = 'block';
  statusDiv.className = 'upload-status loading';
  statusDiv.innerHTML = '⏳ Uploading...';
  
  const formData = new FormData();
  formData.append('file', file);
  
  try {
    const response = await fetch('/api/tools/upload', {
      method: 'POST',
      body: formData
    });
    
    const result = await response.json();
    
    if (response.ok && result.success) {
      statusDiv.className = 'upload-status success';
      statusDiv.innerHTML = `✅ ${result.message}`;
      
      // Reload tools list
      loadTools();
      
      // Hide status after 3 seconds
      setTimeout(() => {
        statusDiv.style.display = 'none';
      }, 3000);
    } else {
      statusDiv.className = 'upload-status error';
      statusDiv.innerHTML = `❌ ${result.error || 'Upload failed'}`;
    }
  } catch (err) {
    statusDiv.className = 'upload-status error';
    statusDiv.innerHTML = `❌ Error: ${err.message}`;
  }
  
  // Clear the input so the same file can be selected again
  input.value = '';
}

async function deleteTool(toolName) {
  if (!confirm(`Are you sure you want to delete "${toolName}.py"?`)) return;
  
  try {
    const response = await fetch(`/api/tools/${toolName}/delete`, {
      method: 'DELETE'
    });
    
    const result = await response.json();
    
    if (response.ok && result.success) {
      alert(result.message);
      loadTools();
    } else {
      alert(`Failed to delete tool: ${result.error || 'Unknown error'}`);
    }
  } catch (err) {
    alert(`Error deleting tool: ${err.message}`);
  }
}

async function runTool(toolName) {
  const outputEl = document.getElementById(`output-${toolName}`);
  const statusEl = document.getElementById(`status-${toolName}`);
  const argsInput = document.getElementById(`args-${toolName}`);
  const card = document.querySelector(`[data-tool="${toolName}"]`);
  const btn = card.querySelector('.btn-primary');
  
  const args = argsInput ? argsInput.value.trim() : '';
  
  btn.disabled = true;
  btn.textContent = '⏳ Running...';
  statusEl.textContent = '';
  outputEl.classList.add('show');
  outputEl.classList.remove('success', 'error');
  outputEl.innerHTML = '<span class="loading-text">Executing tool...</span>';
  
  try {
    const response = await fetch(`/api/tools/${toolName}/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ args: args, timeout: 300 })
    });
    
    const result = await response.json();
    
    if (result.success) {
      outputEl.classList.add('success');
      statusEl.innerHTML = '<span class="success-text">✅ Completed</span>';
      outputEl.textContent = result.output || 'Tool completed successfully (no output)';
    } else {
      outputEl.classList.add('error');
      statusEl.innerHTML = '<span class="error-text">❌ Failed</span>';
      const errorOutput = result.error || result.output || 'Tool failed';
      outputEl.textContent = errorOutput;
    }
  } catch (err) {
    outputEl.classList.add('error');
    statusEl.innerHTML = '<span class="error-text">❌ Error</span>';
    outputEl.textContent = 'Error: ' + err.message;
  } finally {
    btn.disabled = false;
    btn.textContent = '▶️ Run Tool';
  }
}

// ==================== Version Info Functions ====================

// Load version info
async function loadVersionInfo() {
  try {
    const response = await fetch('/api/system/version');
    if (!response.ok) throw new Error('Failed to load version info');
    
    const data = await response.json();
    
    document.getElementById('current-version').textContent = data.version || 'Unknown';
    document.getElementById('current-date').textContent = data.commitDate ? new Date(data.commitDate).toLocaleString() : '--';
  } catch (error) {
    console.error('Error loading version:', error);
    document.getElementById('current-version').textContent = 'Error';
  }
}

// ==================== System / OS Update Functions ====================

// Append a line to the Updates output log.
function osUpdateLog(text, replace = false) {
  const el = document.getElementById('os-update-output');
  if (!el) return;
  if (replace) {
    el.textContent = text;
  } else {
    el.textContent += (el.textContent && el.textContent !== 'Ready.' ? '\n' : '') + text;
  }
  el.scrollTop = el.scrollHeight;
}

// Load read-only host/update status (pending packages, reboot flag, kernel, java).
async function loadOsUpdateStatus() {
  const setText = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val; };
  setText('os-status-version', 'Loading…');
  setText('os-status-pending', '…');
  setText('os-status-kernel', '…');
  setText('os-status-java', '');
  setText('os-status-reboot', '');
  try {
    const response = await fetch('/api/system/os-status');
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Failed to load status');

    setText('os-status-version', data.version || 'unknown');
    setText('os-status-pending', String(data.pending ?? 0) + (data.pending === 1 ? ' package' : ' packages'));
    setText('os-status-kernel', data.kernel || '—');
    setText('os-status-java', data.java || '');

    const rebootEl = document.getElementById('os-status-reboot');
    if (rebootEl) {
      if (data.rebootRequired) {
        rebootEl.textContent = '⚠ Reboot required';
        rebootEl.style.color = '#e0a800';
      } else {
        rebootEl.textContent = 'No reboot needed';
        rebootEl.style.color = '';
      }
    }
  } catch (error) {
    console.error('Error loading OS status:', error);
    setText('os-status-version', 'Error');
    setText('os-status-pending', '—');
    setText('os-status-kernel', '—');
    osUpdateLog('Failed to load host status: ' + error.message);
  }
}

// Run the OS update (mode: 'check' dry-run, or 'apply'). Requires the root password.
async function runOsUpdate(mode) {
  const pwInput = document.getElementById('os-update-password');
  const password = pwInput ? pwInput.value : '';
  if (!password) {
    osUpdateLog('Enter the root password first.', true);
    if (pwInput) pwInput.focus();
    return;
  }

  const verb = mode === 'apply' ? 'Applying OS update' : 'Checking for updates';
  osUpdateLog(verb + '… this can take a while, please wait.', true);
  setOsButtonsDisabled(true);
  try {
    const response = await fetch('/api/system/os-update', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode, password }),
    });
    const data = await response.json();
    if (data.output) osUpdateLog(data.output, true);
    if (data.error) osUpdateLog('\n' + data.error);
    if (!response.ok && !data.output && !data.error) {
      osUpdateLog('Request failed (HTTP ' + response.status + ')');
    }
    if (data.ok) {
      osUpdateLog('\n✓ Done.');
      loadOsUpdateStatus();
    }
  } catch (error) {
    console.error('OS update error:', error);
    osUpdateLog('\nRequest failed: ' + error.message);
  } finally {
    setOsButtonsDisabled(false);
    if (pwInput) pwInput.value = '';
  }
}

// Restart the mserver service. The connection will drop mid-restart; poll until back.
async function restartMserverService() {
  const pwInput = document.getElementById('os-update-password');
  const password = pwInput ? pwInput.value : '';
  if (!password) {
    osUpdateLog('Enter the root password first.', true);
    if (pwInput) pwInput.focus();
    return;
  }
  if (!confirm('Restart the MServer panel service now? The panel will be briefly unavailable.')) {
    return;
  }

  osUpdateLog('Requesting service restart…', true);
  setOsButtonsDisabled(true);
  try {
    const response = await fetch('/api/system/service-restart', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    });
    const data = await response.json();
    if (data.output) osUpdateLog(data.output);
    if (data.error) { osUpdateLog('\n' + data.error); setOsButtonsDisabled(false); return; }
    if (!data.ok) { osUpdateLog('\nRestart request failed.'); setOsButtonsDisabled(false); return; }
    osUpdateLog('\nService is restarting — waiting for it to come back…');
    pollServiceBack();
  } catch (error) {
    console.error('Restart error:', error);
    osUpdateLog('\nRequest failed: ' + error.message);
    setOsButtonsDisabled(false);
  } finally {
    if (pwInput) pwInput.value = '';
  }
}

// Poll the panel until it responds again after a restart.
function pollServiceBack(attempt = 0) {
  const maxAttempts = 30;
  setTimeout(async () => {
    try {
      const r = await fetch('/api/system/version', { cache: 'no-store' });
      if (r.ok) {
        osUpdateLog('✓ Panel is back online.');
        setOsButtonsDisabled(false);
        loadOsUpdateStatus();
        return;
      }
    } catch (_) { /* still down */ }
    if (attempt >= maxAttempts) {
      osUpdateLog('Still waiting — try reloading the page in a moment.');
      setOsButtonsDisabled(false);
      return;
    }
    pollServiceBack(attempt + 1);
  }, 2000);
}

function setOsButtonsDisabled(disabled) {
  document.querySelectorAll('.os-update-buttons button').forEach(b => { b.disabled = disabled; });
}

// ==================== JAR Bucket Functions ====================

let jarBucketTypes = {};
let selectedServerType = null;
let selectedServerTypeInfo = null;
let allVersions = [];
let activeDownloads = {};
let downloadedVersions = {};  // Track which versions are already downloaded

async function loadJarBucketTypes() {
  try {
    const response = await fetch('/api/jar-bucket/types');
    if (!response.ok) throw new Error('Failed to load server types');
    
    jarBucketTypes = await response.json();
    renderJarBucketTypes();
  } catch (err) {
    console.error('Error loading JAR bucket types:', err);
  }
}

function refreshJarBucketTypes() {
  loadJarBucketTypes();
  loadJarBucketDownloaded();
}

function renderJarBucketTypes() {
  // Render Java servers category
  const serversContainer = document.getElementById('jar-bucket-servers');
  if (serversContainer && jarBucketTypes.java) {
    serversContainer.innerHTML = jarBucketTypes.java.map(type => `
      <div class="server-type-card" onclick="selectServerType('${type.id}', ${JSON.stringify(type).replace(/"/g, '&quot;')})">
        <span class="type-icon">${type.icon || '📦'}</span>
        <span class="type-name">${escapeHtml(type.name)}</span>
        <small class="type-desc">${escapeHtml(type.description)}</small>
      </div>
    `).join('') || '<div class="no-data">No Java servers available</div>';
  }
  
  // Render Bedrock category
  const bedrockContainer = document.getElementById('jar-bucket-bedrock');
  if (bedrockContainer && jarBucketTypes.bedrock) {
    bedrockContainer.innerHTML = jarBucketTypes.bedrock.map(type => `
      <div class="server-type-card" onclick="selectServerType('${type.id}', ${JSON.stringify(type).replace(/"/g, '&quot;')})">
        <span class="type-icon">${type.icon || '📦'}</span>
        <span class="type-name">${escapeHtml(type.name)}</span>
        <small class="type-desc">${escapeHtml(type.description)}</small>
      </div>
    `).join('') || '<div class="no-data">No Bedrock servers available</div>';
  }
  
  // Render modded category
  const moddedContainer = document.getElementById('jar-bucket-modded');
  if (moddedContainer && jarBucketTypes.modded) {
    moddedContainer.innerHTML = jarBucketTypes.modded.map(type => `
      <div class="server-type-card" onclick="selectServerType('${type.id}', ${JSON.stringify(type).replace(/"/g, '&quot;')})">
        <span class="type-icon">${type.icon || '📦'}</span>
        <span class="type-name">${escapeHtml(type.name)}</span>
        <small class="type-desc">${escapeHtml(type.description)}</small>
      </div>
    `).join('') || '<div class="no-data">No modded servers available</div>';
  }
}

async function selectServerType(typeId, typeInfo) {
  selectedServerType = typeId;
  selectedServerTypeInfo = typeInfo;
  
  // Update header
  document.getElementById('selected-type-icon').textContent = typeInfo.icon || '📦';
  document.getElementById('selected-type-name').textContent = typeInfo.name;
  
  // Show versions panel
  const versionsPanel = document.getElementById('jar-bucket-versions-panel');
  versionsPanel.style.display = 'block';
  
  // Clear search
  document.getElementById('version-search-input').value = '';
  
  // Load versions
  const versionsList = document.getElementById('jar-bucket-versions-list');
  versionsList.innerHTML = '<div class="loading-text">Loading versions...</div>';
  
  try {
    // Fetch both versions and downloaded files in parallel
    const [versionsResponse, downloadedResponse] = await Promise.all([
      fetch(`/api/jar-bucket/versions/${typeId}`),
      fetch('/api/jar-bucket/list')
    ]);
    
    if (!versionsResponse.ok) throw new Error('Failed to load versions');
    
    const versionsData = await versionsResponse.json();
    allVersions = versionsData.versions || [];
    
    // Build set of downloaded versions for this type
    downloadedVersions = {};
    if (downloadedResponse.ok) {
      const downloadedData = await downloadedResponse.json();
      const typeJars = downloadedData.jars?.[typeId];
      if (typeJars && typeJars.files) {
        for (const file of typeJars.files) {
          if (file.version) {
            downloadedVersions[file.version] = file;
          }
        }
      }
    }
    
    // Update version count
    const countEl = document.getElementById('selected-type-count');
    if (countEl) {
      const downloadedCount = Object.keys(downloadedVersions).length;
      countEl.textContent = `(${allVersions.length} available, ${downloadedCount} downloaded)`;
    }
    
    renderVersions(allVersions);
  } catch (err) {
    versionsList.innerHTML = `<div class="error-text">Failed to load versions: ${err.message}</div>`;
  }
}

function renderVersions(versions) {
  const versionsList = document.getElementById('jar-bucket-versions-list');
  
  if (!versions || versions.length === 0) {
    versionsList.innerHTML = '<div class="no-data">No versions available</div>';
    return;
  }
  
  versionsList.innerHTML = versions.map(version => {
    const isDownloaded = downloadedVersions[version];
    const downloadedFile = isDownloaded ? downloadedVersions[version] : null;
    
    return `
      <div class="version-item ${isDownloaded ? 'downloaded' : ''}">
        <div class="version-info">
          <span class="version-number">${escapeHtml(version)}</span>
          ${isDownloaded ? `<span class="downloaded-badge" title="${escapeAttrValue(downloadedFile?.filename || '')}">✓ Downloaded</span>` : ''}
        </div>
        <button class="btn btn-small ${isDownloaded ? 'btn-secondary' : 'btn-success'}" onclick="downloadJarVersion('${selectedServerType}', '${escapeAttr(version)}')">
          ${isDownloaded ? '🔄 Re-download' : '📥 Download'}
        </button>
      </div>
    `;
  }).join('');
}

function filterVersions() {
  const searchTerm = document.getElementById('version-search-input').value.toLowerCase();
  const filtered = allVersions.filter(v => v.toLowerCase().includes(searchTerm));
  renderVersions(filtered);
}

function closeVersionsPanel() {
  document.getElementById('jar-bucket-versions-panel').style.display = 'none';
  selectedServerType = null;
  selectedServerTypeInfo = null;
  allVersions = [];
  downloadedVersions = {};
}

async function downloadAllVersions() {
  if (!selectedServerType || !allVersions.length) {
    showNotification('No versions to download', 'error');
    return;
  }

  // Filter to only non-downloaded versions
  const toDownload = allVersions.filter(v => !downloadedVersions[v]);

  if (toDownload.length === 0) {
    showNotification('All versions are already downloaded!', 'info');
    return;
  }

  const typeName = selectedServerTypeInfo?.name || selectedServerType;
  const confirmMsg = `Queue ${toDownload.length} download(s) of ${typeName}?\n\n` +
    `They run in the background — you can leave this page. Large batches use significant disk space.`;
  if (!confirm(confirmMsg)) return;

  // Enqueue each as a background task; the queue panel + job pool handle the rest.
  let queued = 0, failed = 0;
  for (const version of toDownload) {
    try {
      const response = await fetch('/api/jar-bucket/queue-download', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: selectedServerType, version })
      });
      if (response.ok) queued++; else failed++;
    } catch (_) {
      failed++;
    }
  }

  showNotification(
    `Queued ${queued} download(s)${failed ? `, ${failed} failed to queue` : ''}`,
    failed ? 'error' : 'success'
  );
  refreshJarDownloadQueue();
}

// --- Download queue (JobManager-backed jar_download tasks) -------------------
// Jar downloads are submitted as background jobs that survive leaving the page
// (and even a panel restart). This panel lists them and polls /api/jobs while
// any are still active.
let jarQueuePollTimer = null;
let jarQueueHadActive = false;

async function refreshJarDownloadQueue() {
  const panel = document.getElementById('jar-download-progress-panel');
  const content = document.getElementById('jar-download-progress-content');
  if (!panel || !content) return;

  let jobs = [];
  try {
    const response = await fetch('/api/jobs');
    if (response.ok) {
      const data = await response.json();
      jobs = (data.jobs || []).filter(j => j.type === 'jar_download');
    }
  } catch (_) { /* keep the last render on transient errors */ }

  jobs.sort((a, b) => (b.created || '').localeCompare(a.created || ''));

  const active = jobs.filter(j => j.status === 'queued' || j.status === 'running');

  if (jobs.length === 0) {
    panel.style.display = 'none';
    content.innerHTML = '';
    if (jarQueuePollTimer) { clearTimeout(jarQueuePollTimer); jarQueuePollTimer = null; }
    jarQueueHadActive = false;
    return;
  }

  panel.style.display = 'block';
  renderJarDownloadQueue(jobs);

  if (active.length > 0) {
    jarQueueHadActive = true;
    if (jarQueuePollTimer) clearTimeout(jarQueuePollTimer);
    jarQueuePollTimer = setTimeout(refreshJarDownloadQueue, 1500);
  } else {
    if (jarQueuePollTimer) { clearTimeout(jarQueuePollTimer); jarQueuePollTimer = null; }
    // On the active -> idle transition, refresh the downloaded list + version badges once.
    if (jarQueueHadActive) {
      jarQueueHadActive = false;
      loadJarBucketDownloaded();
      if (selectedServerType && selectedServerTypeInfo) {
        selectServerType(selectedServerType, selectedServerTypeInfo);
      }
    }
  }
}

function renderJarDownloadQueue(jobs) {
  const content = document.getElementById('jar-download-progress-content');
  const statusMeta = {
    queued:    { icon: '⏸', cls: '',        label: 'Queued' },
    running:   { icon: '⏳', cls: '',        label: 'Downloading' },
    completed: { icon: '✅', cls: 'success', label: 'Done' },
    failed:    { icon: '❌', cls: 'error',   label: 'Failed' },
    cancelled: { icon: '🚫', cls: 'error',   label: 'Cancelled' },
  };

  content.innerHTML = jobs.map(job => {
    const p = job.params || {};
    const name = `${escapeHtml(p.type || '')} ${escapeHtml(p.version || '')}`.trim()
      || escapeHtml(job.title || 'Download');
    const meta = statusMeta[job.status] || { icon: '•', cls: '', label: job.status };
    const pct = Math.max(0, Math.min(100, job.progress || 0));
    const isActive = job.status === 'queued' || job.status === 'running';
    let statusText = meta.label;
    if (job.status === 'failed') statusText = job.error || 'Failed';
    else if (job.status === 'running' && job.message) statusText = job.message;
    const actions = isActive
      ? `<button class="btn btn-small btn-secondary" onclick="cancelJarDownloadJob('${job.id}')">Cancel</button>`
      : `<button class="btn btn-small" onclick="dismissJarDownloadJob('${job.id}')">Dismiss</button>`;
    return `
      <div class="download-item ${meta.cls}">
        <div class="download-info">
          <span class="download-name">${name}</span>
          <span class="download-status ${meta.cls}">${meta.icon} ${escapeHtml(statusText)}</span>
        </div>
        <div class="progress-bar">
          <div class="progress-bar-fill" style="width: ${pct}%"></div>
        </div>
        <div class="download-actions">${actions}</div>
      </div>
    `;
  }).join('');
}

async function cancelJarDownloadJob(jobId) {
  try {
    const response = await fetch(`/api/jobs/${jobId}/cancel`, { method: 'POST' });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      showNotification(data.error || 'Failed to cancel download', 'error');
    }
  } catch (err) {
    showNotification('Network error: ' + err.message, 'error');
  }
  refreshJarDownloadQueue();
}

async function dismissJarDownloadJob(jobId) {
  try {
    await fetch(`/api/jobs/${jobId}`, { method: 'DELETE' });
  } catch (_) { /* ignore */ }
  refreshJarDownloadQueue();
}

async function downloadJarVersion(serverType, version) {
  // Submit the download as a background task and let the queue panel track it,
  // so it keeps running even if the user navigates away.
  try {
    const response = await fetch('/api/jar-bucket/queue-download', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: serverType, version })
    });
    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      showNotification(data.error || 'Failed to queue download', 'error');
      return;
    }

    showNotification(
      data.duplicate ? `${serverType} ${version} is already downloading`
                     : `Queued download: ${serverType} ${version}`,
      data.duplicate ? 'info' : 'success'
    );
    refreshJarDownloadQueue();
  } catch (err) {
    showNotification('Network error: ' + err.message, 'error');
  }
}

async function loadJarBucketDownloaded() {
  const container = document.getElementById('jar-bucket-downloaded-list');
  if (!container) return;
  
  try {
    const response = await fetch('/api/jar-bucket/list');
    const data = await response.json();
    
    if (!data.jars || Object.keys(data.jars).length === 0) {
      container.innerHTML = '<div class="no-jars-text">No downloaded JARs yet. Use the browser above to download server files.</div>';
      return;
    }
    
    let html = '';
    
    for (const [serverType, typeData] of Object.entries(data.jars)) {
      if (!typeData.files || typeData.files.length === 0) continue;
      
      html += `
        <div class="jar-type-group">
          <div class="jar-type-header">
            <span class="jar-type-icon">${typeData.icon || '📦'}</span>
            <span class="jar-type-name">${escapeHtml(typeData.name || serverType)}</span>
            <span class="jar-type-count">${typeData.files.length} file(s)</span>
          </div>
          <div class="jar-type-files">
      `;
      
      for (const file of typeData.files) {
        html += `
          <div class="jar-file-item">
            <div class="jar-file-info">
              <span class="jar-filename">${escapeHtml(file.filename)}</span>
              <span class="jar-version">${escapeHtml(file.version || 'Unknown')}</span>
              <span class="jar-size">${formatBytes(file.size)}</span>
            </div>
            <div class="jar-file-actions">
              <button class="btn btn-small btn-danger" onclick="deleteJarBucket('${serverType}', '${escapeAttr(file.filename)}')" title="Delete">🗑️</button>
            </div>
          </div>
        `;
      }
      
      html += '</div></div>';
    }
    
    container.innerHTML = html || '<div class="no-jars-text">No downloaded JARs yet</div>';
    
  } catch (err) {
    container.innerHTML = `<div class="error-text">Failed to load files: ${err.message}</div>`;
  }
}

async function backupAllJars() {
  const status = document.getElementById('jar-backup-restore-status');
  status.textContent = '⏳ Creating archive…';
  status.className = 'jar-status';

  try {
    const response = await fetch('/api/jar-bucket/backup-all');

    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.error || `Server error ${response.status}`);
    }

    // Trigger browser download
    const blob = await response.blob();
    const disposition = response.headers.get('Content-Disposition') || '';
    const match = disposition.match(/filename="([^"]+)"/);
    const filename = match ? match[1] : 'mserver_jars_backup.zip';

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    status.textContent = `✅ Archive downloaded: ${filename}`;
    status.className = 'jar-status success';
  } catch (err) {
    status.textContent = `❌ Backup failed: ${err.message}`;
    status.className = 'jar-status error';
  }
}

async function restoreAllJars(input) {
  if (!input.files || input.files.length === 0) return;
  const file = input.files[0];
  const status = document.getElementById('jar-backup-restore-status');

  if (!confirm(`Restore JARs from "${file.name}"?\n\nThis will overwrite any downloaded JARs with the same filename.`)) {
    input.value = '';
    return;
  }

  status.textContent = '⏳ Restoring…';
  status.className = 'jar-status';

  try {
    const formData = new FormData();
    formData.append('backup', file);

    const response = await fetch('/api/jar-bucket/restore-all', {
      method: 'POST',
      body: formData
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Server error ${response.status}`);

    status.textContent = `✅ Restored ${data.restored} file(s)`;
    status.className = 'jar-status success';
    loadJarBucketDownloaded();
  } catch (err) {
    status.textContent = `❌ Restore failed: ${err.message}`;
    status.className = 'jar-status error';
  } finally {
    input.value = '';
  }
}

async function deleteJarBucket(serverType, filename) {
  if (!confirm(`Delete ${filename}?`)) return;
  
  try {
    const response = await fetch('/api/jar-bucket/delete', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: serverType, filename })
    });
    
    const data = await response.json();
    
    if (response.ok && data.success) {
      loadJarBucketDownloaded();
    } else {
      alert('Failed to delete: ' + (data.error || 'Unknown error'));
    }
  } catch (err) {
    alert('Error: ' + err.message);
  }
}

// ==================== JAR Download Sources (admin) ====================

function initJarLinksPanel() {
  const panel = document.getElementById('jar-links-panel');
  if (!panel) return;
  // Backend endpoints are admin-only (wildcard permission group)
  if (!window.currentUser || !currentUser.permissions || !currentUser.permissions.includes('*')) return;
  panel.style.display = '';
  loadJarLinks();
}

async function loadJarLinks() {
  const container = document.getElementById('jar-links-list');
  if (!container) return;
  try {
    const response = await fetch('/api/jar-bucket/links');
    if (!response.ok) throw new Error('Failed to load link configuration');
    const data = await response.json();
    renderJarLinks(data.types || {});
    setJarLinksStatus('');
  } catch (err) {
    container.innerHTML = `<div class="error-text">${escapeHtml(err.message)}</div>`;
  }
}

function renderJarLinks(types) {
  const container = document.getElementById('jar-links-list');
  container.innerHTML = Object.keys(types).map(typeId => {
    const type = types[typeId];
    const fields = Object.entries(type.fields).map(([field, info]) => {
      const placeholders = (info.placeholders && info.placeholders.length)
        ? ` <small class="jar-links-placeholders">(must contain ${info.placeholders.map(p => '{' + p + '}').join(', ')})</small>`
        : '';
      return `
        <div class="form-group">
          <label>${escapeHtml(info.label)}${placeholders}</label>
          <input type="text" class="form-control jar-link-input" data-type="${escapeAttrValue(typeId)}" data-field="${escapeAttrValue(field)}"
                 value="${escapeAttrValue(info.override || '')}" placeholder="${escapeAttrValue(info.default)}">
        </div>
      `;
    }).join('');
    const spigotNote = typeId === 'spigot'
      ? '<span class="jar-links-note">⚠️ Cannot be auto-downloaded — JARs must be compiled with BuildTools</span>'
      : '';
    return `
      <div class="jar-links-card">
        <div class="jar-links-card-header">
          <span class="type-icon">${type.icon || '📦'}</span>
          <strong>${escapeHtml(type.name)}</strong>
          ${spigotNote}
          <div class="jar-links-card-actions">
            <button class="btn btn-small" onclick="testJarLinks('${escapeAttr(typeId)}')" title="Test the saved links against upstream">🧪 Test</button>
            <button class="btn btn-small" onclick="resetJarLinks('${escapeAttr(typeId)}')" title="Remove all overrides for this type">↩️ Reset to Default</button>
          </div>
        </div>
        <div class="jar-links-fields">${fields}</div>
        <div class="jar-links-test-result" id="jar-links-test-${escapeAttrValue(typeId)}"></div>
      </div>
    `;
  }).join('') || '<div class="no-data">No configurable server types</div>';
}

function setJarLinksStatus(message, isError = false) {
  const status = document.getElementById('jar-links-status');
  if (!status) return;
  status.textContent = message;
  status.className = 'jar-status' + (message ? (isError ? ' error' : ' success') : '');
}

async function saveJarLinks() {
  const overrides = {};
  document.querySelectorAll('.jar-link-input').forEach(input => {
    const type = input.dataset.type;
    const field = input.dataset.field;
    if (!overrides[type]) overrides[type] = {};
    overrides[type][field] = input.value.trim(); // empty = reset to default
  });

  try {
    const response = await fetch('/api/jar-bucket/links', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ overrides })
    });
    const data = await response.json();
    if (!response.ok) {
      const detail = (data.errors && data.errors.length) ? data.errors.join('; ') : (data.error || 'Save failed');
      setJarLinksStatus(detail, true);
      return;
    }
    renderJarLinks(data.types || {});
    setJarLinksStatus('Download links saved. Version cache cleared.');
    showNotification('JAR download links updated', 'success');
    loadJarBucketTypes(); // type cards show the effective apiUrl
  } catch (err) {
    setJarLinksStatus('Error: ' + err.message, true);
  }
}

async function resetJarLinks(typeId) {
  if (!confirm(`Reset all ${typeId} download links to their built-in defaults?`)) return;
  const overrides = { [typeId]: {} };
  document.querySelectorAll(`.jar-link-input[data-type="${typeId}"]`).forEach(input => {
    overrides[typeId][input.dataset.field] = '';
  });
  try {
    const response = await fetch('/api/jar-bucket/links', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ overrides })
    });
    const data = await response.json();
    if (!response.ok) {
      setJarLinksStatus(data.error || 'Reset failed', true);
      return;
    }
    renderJarLinks(data.types || {});
    setJarLinksStatus(`${typeId} links reset to defaults.`);
    loadJarBucketTypes();
  } catch (err) {
    setJarLinksStatus('Error: ' + err.message, true);
  }
}

async function testJarLinks(typeId) {
  const resultEl = document.getElementById(`jar-links-test-${typeId}`);
  if (resultEl) {
    resultEl.textContent = '⏳ Testing saved links against upstream...';
    resultEl.className = 'jar-links-test-result';
  }
  try {
    const response = await fetch(`/api/jar-bucket/links/test/${encodeURIComponent(typeId)}`, { method: 'POST' });
    const data = await response.json();
    if (resultEl) {
      if (response.ok && data.success) {
        resultEl.textContent = '✅ ' + (data.message || 'Links working');
        resultEl.className = 'jar-links-test-result success';
      } else {
        resultEl.textContent = '❌ ' + (data.error || 'Test failed');
        resultEl.className = 'jar-links-test-result error';
      }
    }
  } catch (err) {
    if (resultEl) {
      resultEl.textContent = '❌ ' + err.message;
      resultEl.className = 'jar-links-test-result error';
    }
  }
}

// Toggle collapsible tool panels
function toggleToolPanel(header) {
  const panel = header.closest('.tool-panel');
  const body = panel.querySelector('.tool-panel-body');
  const indicator = header.querySelector('.collapse-indicator');
  
  if (body.style.display === 'none') {
    body.style.display = 'block';
    panel.classList.remove('collapsed');
    if (indicator) indicator.textContent = '▼';
  } else {
    body.style.display = 'none';
    panel.classList.add('collapsed');
    if (indicator) indicator.textContent = '▶';
  }
}

// ==================== User Management Functions ====================
// Note: Utility functions (formatBytes, escapeHtml) are in utils.js

async function loadUsers() {
  try {
    const response = await fetch('/api/admin/users');
    if (!response.ok) throw new Error('Failed to load users');
    
    const data = await response.json();
    const users = data.users || [];
    const approvedUsers = users.filter(u => u.approved);
    
    const usersList = document.getElementById('users-list');
    if (approvedUsers.length === 0) {
      usersList.innerHTML = `
        <div class="user-mgmt-empty">
          <h3>No Users</h3>
          <p>No registered users found</p>
        </div>
      `;
    } else {
      usersList.innerHTML = `
        <table class="user-mgmt-table">
          <thead>
            <tr>
              <th>Username</th>
              <th>Display Name</th>
              <th>Email</th>
              <th>Group</th>
              <th>Status</th>
              <th>MFA</th>
              <th>Created</th>
              <th>Last Login</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${approvedUsers.map(u => `
              <tr>
                <td>${escapeHtml(u.username)}</td>
                <td>${u.name ? escapeHtml(u.name) : '<span class="text-muted">Not set</span>'}</td>
                <td>${u.email ? escapeHtml(u.email) : '<span class="text-muted">Not set</span>'}</td>
                <td><span class="group-badge">${escapeHtml(u.groupName || 'None')}</span></td>
                <td>${u.locked
                  ? `<span class="badge badge-danger" title="${u.disabledAt ? 'Locked after too many failed logins on ' + escapeAttrValue(new Date(u.disabledAt).toLocaleString()) : 'Account disabled'}">🔒 Locked</span>`
                  : '<span class="badge badge-success">Active</span>'}</td>
                <td>${u.mfaEnabled ? '<span class="badge badge-success">Enabled</span>' : '<span class="badge badge-secondary">Disabled</span>'}</td>
                <td>${new Date(u.created).toLocaleDateString()}</td>
                <td>${u.lastLogin ? new Date(u.lastLogin).toLocaleDateString() : 'Never'}</td>
                <td class="user-mgmt-actions">
                  ${u.isAntiLockout
                    ? '<span class="text-muted" title="Built-in emergency admin. Managed by the system and cannot be edited or deleted.">🔒 System account</span>'
                    : `${u.locked ? `<button class="btn btn-small btn-success" onclick="unlockUser('${u.id}', '${escapeAttr(u.username)}')">🔓 Unlock</button>` : ''}
                  <button class="btn btn-small btn-primary" onclick="openEditUserModal('${u.id}')">✏️ Edit</button>
                  <button class="btn btn-small btn-danger" onclick="deleteUser('${u.id}', '${escapeAttr(u.username)}')">🗑️</button>`}
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    }
  } catch (err) {
    console.error('Failed to load users:', err);
    document.getElementById('users-list').innerHTML = `
      <div class="user-mgmt-empty">
        <h3>Error Loading Users</h3>
        <p>${err.message}</p>
      </div>
    `;
  }
}

// ==================== Approvals Functions ====================

async function loadPendingApprovals() {
  await Promise.all([loadPendingUsers(), loadPendingServers(), loadPendingActions()]);
}

async function loadPendingUsers() {
  try {
    const response = await fetch('/api/admin/users');
    if (!response.ok) throw new Error('Failed to load users');
    
    const data = await response.json();
    const users = data.users || [];
    const pendingUsers = users.filter(u => !u.approved);
    
    // Update count badge
    document.getElementById('pending-users-count').textContent = pendingUsers.length;
    
    const pendingList = document.getElementById('pending-users-list');
    if (pendingUsers.length === 0) {
      pendingList.innerHTML = `
        <div class="approval-empty">
          <p>No pending user registrations</p>
        </div>
      `;
    } else {
      pendingList.innerHTML = `
        <div class="approval-items">
          ${pendingUsers.map(u => `
            <div class="approval-item">
              <div class="approval-item-info">
                <span class="approval-item-name">${escapeHtml(u.username)}</span>
                <span class="approval-item-date">Registered ${new Date(u.created).toLocaleDateString()}</span>
              </div>
              <div class="approval-item-actions">
                <button class="btn btn-small btn-success" onclick="approveUser('${u.id}')">Approve</button>
                <button class="btn btn-small btn-danger" onclick="deleteUser('${u.id}', '${escapeAttr(u.username)}')">Reject</button>
              </div>
            </div>
          `).join('')}
        </div>
      `;
    }
  } catch (err) {
    console.error('Failed to load pending users:', err);
    document.getElementById('pending-users-list').innerHTML = `
      <div class="approval-empty">
        <p>Error loading pending users</p>
      </div>
    `;
  }
}

async function loadPendingServers() {
  try {
    const response = await fetch('/api/admin/servers/pending');
    if (!response.ok) {
      // Endpoint may not exist yet - show empty state
      document.getElementById('pending-servers-count').textContent = '0';
      document.getElementById('pending-servers-list').innerHTML = `
        <div class="approval-empty">
          <p>No pending server requests</p>
        </div>
      `;
      return;
    }
    
    const data = await response.json();
    const pendingServers = data.servers || [];
    
    // Update count badge
    document.getElementById('pending-servers-count').textContent = pendingServers.length;
    
    const pendingList = document.getElementById('pending-servers-list');
    if (pendingServers.length === 0) {
      pendingList.innerHTML = `
        <div class="approval-empty">
          <p>No pending server requests</p>
        </div>
      `;
    } else {
      pendingList.innerHTML = `
        <div class="approval-items">
          ${pendingServers.map(s => `
            <div class="approval-item">
              <div class="approval-item-info">
                <span class="approval-item-name">${escapeHtml(s.name)}</span>
                <span class="approval-item-meta">Requested by ${escapeHtml(s.owner || 'Unknown')} • ${s.type || 'Server'}</span>
                <span class="approval-item-date">Requested ${new Date(s.created).toLocaleDateString()}</span>
              </div>
              <div class="approval-item-actions">
                <button class="btn btn-small btn-success" onclick="approveServer('${s.id}')">Approve</button>
                <button class="btn btn-small btn-danger" onclick="rejectServer('${s.id}', '${escapeAttr(s.name)}')">Reject</button>
              </div>
            </div>
          `).join('')}
        </div>
      `;
    }
  } catch (err) {
    console.error('Failed to load pending servers:', err);
    document.getElementById('pending-servers-count').textContent = '0';
    document.getElementById('pending-servers-list').innerHTML = `
      <div class="approval-empty">
        <p>No pending server requests</p>
      </div>
    `;
  }
}

async function approveServer(serverId) {
  try {
    const response = await fetch(`/api/admin/servers/${serverId}/approve`, { method: 'POST' });
    if (!response.ok) throw new Error('Failed to approve server');
    loadPendingServers();
  } catch (err) {
    console.error('Failed to approve server:', err);
    alert('Failed to approve server: ' + err.message);
  }
}

async function rejectServer(serverId, serverName) {
  if (!confirm(`Are you sure you want to reject the server request "${serverName}"? This will delete the request.`)) return;
  
  try {
    const response = await fetch(`/api/admin/servers/${serverId}/reject`, { method: 'DELETE' });
    if (!response.ok) throw new Error('Failed to reject server');
    loadPendingServers();
  } catch (err) {
    console.error('Failed to reject server:', err);
    alert('Failed to reject server: ' + err.message);
  }
}

async function approveUser(userId) {
  try {
    const response = await fetch(`/api/admin/users/${userId}/approve`, { method: 'POST' });
    if (!response.ok) throw new Error('Failed to approve user');
    loadUsers();
  } catch (err) {
    console.error('Failed to approve user:', err);
    alert('Failed to approve user: ' + err.message);
  }
}

async function unlockUser(userId, username) {
  if (!confirm(`Unlock account "${username}"? This clears the lockout and resets their failed login attempts.`)) return;

  try {
    const response = await fetch(`/api/admin/users/${userId}/enable`, { method: 'POST' });
    const data = await response.json();
    if (!response.ok || !data.success) throw new Error(data.error || 'Failed to unlock account');
    showNotification(`Account "${username}" unlocked`, 'success');
    loadUsers();
  } catch (err) {
    console.error('Failed to unlock user:', err);
    showNotification('Failed to unlock account: ' + err.message, 'error');
  }
}

async function deleteUser(userId, username) {
  if (!confirm(`Are you sure you want to delete user "${username}"?`)) return;
  
  try {
    const response = await fetch(`/api/admin/users/${userId}`, { method: 'DELETE' });
    if (!response.ok) throw new Error('Failed to delete user');
    loadUsers();
  } catch (err) {
    console.error('Failed to delete user:', err);
    alert('Failed to delete user: ' + err.message);
  }
}

// ==================== Edit User Functions ====================

let editingUserId = null;

async function openEditUserModal(userId) {
  try {
    const response = await fetch(`/api/admin/users/${userId}`);
    if (!response.ok) throw new Error('Failed to load user');
    
    const data = await response.json();
    const user = data.user;
    
    editingUserId = userId;
    
    // Populate the modal fields
    document.getElementById('edit-user-display-username').textContent = user.username;
    const roleDisplay = document.getElementById('edit-user-display-role');
    roleDisplay.textContent = (user.groupName || 'No Group').toUpperCase();
    roleDisplay.className = 'profile-info-value profile-role-badge group-badge';

    document.getElementById('edit-user-username').value = user.username;
    document.getElementById('edit-user-name').value = user.name || '';
    document.getElementById('edit-user-email').value = user.email || '';
    await populateGroupSelect('edit-user-group', user.groupId);
    
    // Update MFA status display
    const mfaStatusContainer = document.getElementById('edit-user-mfa-status');
    if (user.mfaEnabled) {
      mfaStatusContainer.innerHTML = `
        <p class="mfa-info success-text">✓ Two-factor authentication is enabled on this account.</p>
        <button class="btn btn-danger" onclick="clearUserMFA('${userId}')">Clear MFA</button>
      `;
    } else {
      mfaStatusContainer.innerHTML = `
        <p class="mfa-info">Two-factor authentication is not enabled on this account.</p>
      `;
    }
    
    // Clear password field
    document.getElementById('edit-user-new-password').value = '';
    
    // Show modal
    document.getElementById('edit-user-modal').style.display = 'flex';
  } catch (err) {
    console.error('Failed to load user:', err);
    alert('Failed to load user: ' + err.message);
  }
}

function closeEditUserModal() {
  document.getElementById('edit-user-modal').style.display = 'none';
  editingUserId = null;
}

async function saveEditUser() {
  if (!editingUserId) return;
  
  const username = document.getElementById('edit-user-username').value.trim();
  const name = document.getElementById('edit-user-name').value.trim();
  const email = document.getElementById('edit-user-email').value.trim();
  const groupId = document.getElementById('edit-user-group').value;
  const newPassword = document.getElementById('edit-user-new-password').value;
  
  if (!username) {
    showNotification('Username is required', 'error');
    return;
  }
  
  try {
    // Update username
    const usernameResponse = await fetch(`/api/admin/users/${editingUserId}/username`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    
    if (!usernameResponse.ok) {
      const data = await usernameResponse.json();
      showNotification(data.error || 'Failed to update username', 'error');
      return;
    }
    
    // Update name
    const nameResponse = await fetch(`/api/admin/users/${editingUserId}/name`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name })
    });
    
    if (!nameResponse.ok) {
      const data = await nameResponse.json();
      showNotification(data.error || 'Failed to update display name', 'error');
      return;
    }
    
    // Update email
    const emailResponse = await fetch(`/api/admin/users/${editingUserId}/email`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    
    if (!emailResponse.ok) {
      const data = await emailResponse.json();
      showNotification(data.error || 'Failed to update email', 'error');
      return;
    }
    
    // Update group
    const groupResponse = await fetch(`/api/admin/users/${editingUserId}/group`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ groupId })
    });

    if (!groupResponse.ok) {
      const data = await groupResponse.json();
      showNotification(data.error || 'Failed to update group', 'error');
      return;
    }
    
    // Update password if provided
    if (newPassword) {
      const passwordError = validatePassword(newPassword);
      if (passwordError) {
        showNotification(passwordError, 'error');
        return;
      }
      
      const passwordResponse = await fetch(`/api/admin/users/${editingUserId}/password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: newPassword })
      });
      
      if (!passwordResponse.ok) {
        const data = await passwordResponse.json();
        showNotification(data.error || 'Failed to reset password', 'error');
        return;
      }
    }
    
    showNotification('User updated successfully', 'success');
    closeEditUserModal();
    loadUsers();
  } catch (err) {
    console.error('Failed to update user:', err);
    showNotification('Failed to update user: ' + err.message, 'error');
  }
}

async function clearUserMFA(userId) {
  if (!confirm('Are you sure you want to clear MFA for this user? They will need to set it up again.')) {
    return;
  }
  
  try {
    const response = await fetch(`/api/admin/users/${userId}/mfa`, {
      method: 'DELETE'
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      showNotification(data.error || 'Failed to clear MFA', 'error');
      return;
    }
    
    showNotification('MFA cleared successfully', 'success');
    
    // Refresh the modal to show updated MFA status
    openEditUserModal(userId);
  } catch (err) {
    console.error('Failed to clear MFA:', err);
    showNotification('Failed to clear MFA: ' + err.message, 'error');
  }
}

// ==================== Add User Functions ====================

async function openAddUserModal() {
  await populateGroupSelect('new-group');
  document.getElementById('add-user-modal').style.display = 'flex';
  document.getElementById('new-username').focus();
}

function closeAddUserModal() {
  document.getElementById('add-user-modal').style.display = 'none';
  document.getElementById('add-user-form').reset();
}

async function createUser(event) {
  event.preventDefault();
  
  const username = document.getElementById('new-username').value.trim();
  const email = document.getElementById('new-email').value.trim();
  const password = document.getElementById('new-password').value;
  const groupId = document.getElementById('new-group').value;

  if (!username || !password) {
    alert('Please fill in all fields');
    return;
  }

  const passwordError = validatePassword(password);
  if (passwordError) {
    alert(passwordError);
    return;
  }

  try {
    const response = await fetch('/api/admin/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password, groupId })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Failed to create user');
    }

    alert('User created successfully!');
    closeAddUserModal();
    loadUsers();
  } catch (err) {
    console.error('Failed to create user:', err);
    alert('Failed to create user: ' + err.message);
  }
}

// ==================== App Settings Functions ====================

async function loadAppSettings() {
  try {
    const response = await fetch('/api/settings/app');
    if (response.ok) {
      const settings = await response.json();
      
      document.getElementById('enable-registration').checked = settings.enableRegistration ?? true;
      document.getElementById('global-max-backups').value = settings.globalMaxBackups ?? 10;
      document.getElementById('auto-delete-expired-backups').checked = settings.autoDeleteExpiredBackups ?? false;
    }

    // Load action policies
    await loadPolicies();
    
    // Load MFA settings
    const mfaResponse = await fetch('/api/settings/mfa');
    if (mfaResponse.ok) {
      const mfaSettings = await mfaResponse.json();
      document.getElementById('require-mfa-admins').checked = mfaSettings.requireMfaForAdmins ?? false;
      document.getElementById('require-mfa-all').checked = mfaSettings.requireMfaForAllUsers ?? false;
    }
    
    // Load SMTP settings
    await loadSmtpSettings();
    // Load Webhook settings
    await loadWebhookSettings();
    // Load Email Templates
    await loadEmailTemplates();
    // Load Network & Connectivity settings
    await loadNetworkSettings();
  } catch (err) {
    console.error('Failed to load app settings:', err);
  }
}

async function loadNetworkSettings() {
  try {
    const response = await fetch('/api/settings/network');
    if (response.ok) {
      const net = await response.json();
      const branding = await fetch('/api/settings/branding').then(r => r.json());
      document.getElementById('base-url').value = branding.baseUrl || '';
      document.getElementById('game-hostname').value = branding.gameHostname || '';
      document.getElementById('cors-origins').value = net.corsOrigins || '';
      document.getElementById('session-cookie-secure').checked = net.sessionCookieSecure ?? false;
      document.getElementById('session-cookie-domain').value = net.sessionCookieDomain || '';
      document.getElementById('session-lifetime').value = net.permanentSessionLifetime ?? 604800;
      document.getElementById('network-port').value = net.port ?? 3000;
    }
  } catch (err) {
    console.error('Failed to load network settings:', err);
  }
}

async function saveNetworkSettings() {
  try {
    const baseUrl = document.getElementById('base-url').value;
    const gameHostname = document.getElementById('game-hostname').value;
    const brandingFd = new FormData();
    brandingFd.append('baseUrl', baseUrl);
    brandingFd.append('gameHostname', gameHostname);
    const currentBranding = await fetch('/api/settings/branding').then(r => r.json());
    brandingFd.append('siteTitle', currentBranding.siteTitle || '');
    brandingFd.append('footerAddition', currentBranding.footerAddition || '');
    await fetch('/api/settings/branding', { method: 'PUT', body: brandingFd });

    // Save network/.env settings
    const payload = {
      corsOrigins: document.getElementById('cors-origins').value,
      sessionCookieSecure: document.getElementById('session-cookie-secure').checked,
      sessionCookieDomain: document.getElementById('session-cookie-domain').value,
      permanentSessionLifetime: parseInt(document.getElementById('session-lifetime').value, 10) || 604800,
    };

    const response = await fetch('/api/settings/network', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (response.ok) {
      const result = await response.json();
      showNotification(result.message || 'Network settings saved.', 'success');
    } else {
      const err = await response.json();
      showNotification('Failed to save network settings: ' + (err.error || 'Unknown error'), 'error');
    }
  } catch (err) {
    showNotification('Failed to save network settings: ' + err.message, 'error');
  }
}

async function deleteAllExpiredBackups() {
  if (!await confirmAction('Delete all expired backups across every server? This cannot be undone.', { title: 'Delete All Expired Backups', icon: '🗑️', okText: 'Delete All Expired', okClass: 'btn-danger' })) return;
  try {
    const response = await fetch('/api/backups/delete-expired', { method: 'POST' });
    const result = await response.json();
    if (!response.ok) {
      showNotification(result.error || 'Failed to delete expired backups', 'error');
      return;
    }
    showNotification(`Deleted ${result.deleted} expired backup(s) across all servers`, 'success');
  } catch (err) {
    console.error('Failed to delete expired backups:', err);
    showNotification('Failed to delete expired backups', 'error');
  }
}

async function loadSmtpSettings() {
  try {
    const response = await fetch('/api/settings/smtp');
    if (response.ok) {
      const smtp = await response.json();
      
      document.getElementById('smtp-enabled').checked = smtp.enabled ?? false;
      document.getElementById('smtp-host').value = smtp.host ?? '';
      document.getElementById('smtp-port').value = smtp.port ?? 587;
      document.getElementById('smtp-secure').checked = smtp.secure ?? true;
      document.getElementById('smtp-username').value = smtp.username ?? '';
      // Password is not returned from API for security, only show placeholder if configured
      document.getElementById('smtp-password').value = '';
      document.getElementById('smtp-password').placeholder = smtp.host ? '••••••••' : 'Password';
      document.getElementById('smtp-from-email').value = smtp.fromEmail ?? '';
      document.getElementById('smtp-from-name').value = smtp.fromName ?? '';
      
      toggleSmtpFields();
    }
  } catch (err) {
    console.error('Failed to load SMTP settings:', err);
  }
}

function toggleSmtpFields() {
  const enabled = document.getElementById('smtp-enabled').checked;
  const smtpConfigSection = document.getElementById('smtp-config-section');
  
  if (smtpConfigSection) {
    smtpConfigSection.style.display = enabled ? 'block' : 'none';
  }
}

async function saveAppSettings() {
  const settings = {
    enableRegistration: document.getElementById('enable-registration').checked,
    globalMaxBackups: parseInt(document.getElementById('global-max-backups').value) || 0,
    autoDeleteExpiredBackups: document.getElementById('auto-delete-expired-backups').checked
  };
  
  const mfaSettings = {
    requireMfaForAdmins: document.getElementById('require-mfa-admins').checked,
    requireMfaForAllUsers: document.getElementById('require-mfa-all').checked
  };
  
  try {
    const response = await fetch('/api/settings/app', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings)
    });
    
    if (!response.ok) {
      throw new Error('Failed to save app settings');
    }
    
    // Save MFA settings
    const mfaResponse = await fetch('/api/settings/mfa', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(mfaSettings)
    });
    
    if (!mfaResponse.ok) {
      throw new Error('Failed to save MFA settings');
    }
  } catch (err) {
    console.error('Failed to save app settings:', err);
    alert('Failed to save settings: ' + err.message);
  }
}

async function saveSmtpSettings() {
  const smtpSettings = {
    enabled: document.getElementById('smtp-enabled').checked,
    host: document.getElementById('smtp-host').value.trim(),
    port: parseInt(document.getElementById('smtp-port').value) || 587,
    secure: document.getElementById('smtp-secure').checked,
    username: document.getElementById('smtp-username').value.trim(),
    fromEmail: document.getElementById('smtp-from-email').value.trim(),
    fromName: document.getElementById('smtp-from-name').value.trim()
  };
  
  // Only include password if it was changed (not empty)
  const password = document.getElementById('smtp-password').value;
  if (password) {
    smtpSettings.password = password;
  }
  
  // Validate required fields if SMTP is enabled
  if (smtpSettings.enabled) {
    if (!smtpSettings.host) {
      showNotification('SMTP host is required', 'error');
      return;
    }
    if (!smtpSettings.fromEmail) {
      showNotification('From email is required', 'error');
      return;
    }
  }
  
  try {
    const response = await fetch('/api/settings/smtp', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(smtpSettings)
    });
    
    if (!response.ok) {
      const data = await response.json();
      throw new Error(data.error || 'Failed to save SMTP settings');
    }
    
    showNotification('SMTP settings saved successfully', 'success');
    
    // Clear password field after save
    document.getElementById('smtp-password').value = '';
    document.getElementById('smtp-password').placeholder = smtpSettings.host ? '••••••••' : 'Password';
  } catch (err) {
    console.error('Failed to save SMTP settings:', err);
    showNotification('Failed to save SMTP settings: ' + err.message, 'error');
  }
}

async function testSmtpSettings() {
  const testEmail = document.getElementById('smtp-test-email')?.value.trim();
  
  if (!testEmail) {
    showNotification('Please enter a test email address', 'error');
    return;
  }
  
  // Basic email validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(testEmail)) {
    showNotification('Please enter a valid email address', 'error');
    return;
  }
  
  const testBtn = document.querySelector('.smtp-actions button');
  if (testBtn) {
    testBtn.disabled = true;
    testBtn.textContent = 'Sending...';
  }
  
  try {
    const response = await fetch('/api/settings/smtp/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: testEmail })
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Failed to send test email');
    }
    
    showNotification('Test email sent successfully! Check your inbox.', 'success');
  } catch (err) {
    console.error('Failed to send test email:', err);
    showNotification('Failed to send test email: ' + err.message, 'error');
  } finally {
    if (testBtn) {
      testBtn.disabled = false;
      testBtn.textContent = '📧 Send Test Email';
    }
  }
}

// ==================== API Manager Functions ====================

let apiKeysCache = [];

async function loadApiManager() {
  await loadApiKeys();
  await loadApiStats();
  updateApiEndpoint();
}

function updateApiEndpoint() {
  const endpoint = document.getElementById('api-endpoint');
  if (endpoint) {
    const baseUrl = window.location.origin;
    endpoint.textContent = `${baseUrl}/api/v1/`;
  }
}

async function loadApiKeys() {
  const listEl = document.getElementById('api-keys-list');
  
  try {
    const response = await fetch('/api/v1/keys');
    
    if (response.status === 401) {
      window.location.href = '/login.html';
      return;
    }
    
    if (response.status === 403) {
      listEl.innerHTML = '<div class="error-text">Admin access required to manage API keys</div>';
      return;
    }
    
    if (!response.ok) {
      listEl.innerHTML = '<div class="error-text">Failed to load API keys</div>';
      return;
    }
    
    const data = await response.json();
    apiKeysCache = data.keys || [];
    
    displayApiKeys(apiKeysCache);
    document.getElementById('api-active-keys').textContent = apiKeysCache.filter(k => k.active).length;
  } catch (err) {
    console.error('Failed to load API keys:', err);
    listEl.innerHTML = '<div class="error-text">Failed to load API keys: ' + escapeHtml(err.message) + '</div>';
  }
}

function displayApiKeys(keys) {
  const listEl = document.getElementById('api-keys-list');
  
  if (keys.length === 0) {
    listEl.innerHTML = '<div class="empty-state">No API keys created yet. Create one to allow external API access.</div>';
    return;
  }
  
  const keyCards = keys.map(key => {
    const statusClass = key.active ? 'online' : 'offline';
    const statusText = key.active ? 'Active' : 'Inactive';
    const createdAt = key.createdAt ? new Date(key.createdAt).toLocaleString() : 'Unknown';
    const lastUsed = key.lastUsed ? new Date(key.lastUsed).toLocaleString() : 'Never';
    const expiresAt = key.expiresAt ? new Date(key.expiresAt).toLocaleString() : 'Never';
    
    // Mask the key for display (show first 8 and last 4 characters)
    const maskedKey = key.key ? `${key.key.substring(0, 8)}...${key.key.substring(key.key.length - 4)}` : '••••••••';
    
    return `
      <div class="api-key-item">
        <div class="api-key-header">
          <div class="api-key-title">
            <h4>🔑 ${escapeHtml(key.name || 'Unnamed Key')}</h4>
            <span class="api-key-status ${statusClass}">${statusText}</span>
          </div>
          <div class="api-key-actions">
            <button class="btn btn-small" onclick="copyApiKey('${escapeAttr(key.id)}')" title="Copy Key">📋</button>
            <button class="btn btn-small ${key.active ? 'btn-warning' : 'btn-success'}" onclick="toggleApiKey('${escapeAttr(key.id)}')" title="${key.active ? 'Disable' : 'Enable'}">
              ${key.active ? '⏸️' : '▶️'}
            </button>
            <button class="btn btn-small btn-danger" onclick="deleteApiKey('${escapeAttr(key.id)}')" title="Delete">🗑️</button>
          </div>
        </div>
        
        <div class="api-key-details">
          <div class="api-key-info-grid">
            <div class="info-item">
              <span class="info-label">Key:</span>
              <code class="info-value api-key-masked">${maskedKey}</code>
            </div>
            <div class="info-item">
              <span class="info-label">Created:</span>
              <span class="info-value">${createdAt}</span>
            </div>
            <div class="info-item">
              <span class="info-label">Last Used:</span>
              <span class="info-value">${lastUsed}</span>
            </div>
            <div class="info-item">
              <span class="info-label">Expires:</span>
              <span class="info-value">${expiresAt}</span>
            </div>
            <div class="info-item">
              <span class="info-label">Requests:</span>
              <span class="info-value">${key.requestCount || 0}</span>
            </div>
            <div class="info-item">
              <span class="info-label">Rate Limit:</span>
              <span class="info-value">${key.rateLimit || 'Default'}/min</span>
            </div>
          </div>
          
          <div class="api-key-permissions">
            <strong>Permissions:</strong>
            <div class="permissions-list">
              ${(key.permissions || ['read']).map(p => `<span class="permission-badge">${escapeHtml(p)}</span>`).join('')}
            </div>
          </div>
        </div>
      </div>
    `;
  }).join('');
  
  listEl.innerHTML = keyCards;
}

async function loadApiStats() {
  try {
    const response = await fetch('/api/v1/stats');
    
    if (!response.ok) {
      console.error('Failed to load API stats');
      return;
    }
    
    const data = await response.json();
    
    document.getElementById('api-total-requests').textContent = data.totalRequests || 0;
    document.getElementById('api-successful-requests').textContent = data.successfulRequests || 0;
    document.getElementById('api-failed-requests').textContent = data.failedRequests || 0;
  } catch (err) {
    console.error('Failed to load API stats:', err);
  }
}

function refreshApiStats() {
  loadApiStats();
  loadApiKeys();
}

function openCreateApiKeyModal() {
  // For now, use a simple prompt - can be enhanced with a proper modal later
  const keyName = prompt('Enter a name for this API key:');
  if (keyName && keyName.trim()) {
    createApiKey(keyName.trim());
  }
}

async function createApiKey(name) {
  try {
    const response = await fetch('/api/v1/keys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, permissions: ['read'] })
    });
    
    if (!response.ok) {
      const error = await response.json();
      alert('Failed to create API key: ' + (error.error || 'Unknown error'));
      return;
    }
    
    const data = await response.json();
    
    // Show the full key to the user (only shown once)
    alert(`API Key created successfully!\n\nKey: ${data.key}\n\n⚠️ Copy this key now - it won't be shown again!`);
    
    loadApiKeys();
  } catch (err) {
    console.error('Failed to create API key:', err);
    alert('Failed to create API key: ' + err.message);
  }
}

async function copyApiKey(keyId) {
  const key = apiKeysCache.find(k => k.id === keyId);
  if (!key || !key.key) {
    alert('Cannot copy key - key data not available. For security, full keys are only shown when created.');
    return;
  }
  
  try {
    await navigator.clipboard.writeText(key.key);
    alert('API key copied to clipboard!');
  } catch (err) {
    console.error('Failed to copy:', err);
    alert('Failed to copy to clipboard');
  }
}

async function toggleApiKey(keyId) {
  const key = apiKeysCache.find(k => k.id === keyId);
  if (!key) return;
  
  try {
    const response = await fetch(`/api/v1/keys/${keyId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ active: !key.active })
    });
    
    if (!response.ok) {
      alert('Failed to update API key');
      return;
    }
    
    loadApiKeys();
  } catch (err) {
    console.error('Failed to toggle API key:', err);
    alert('Failed to update API key: ' + err.message);
  }
}

async function deleteApiKey(keyId) {
  if (!confirm('Are you sure you want to delete this API key? This cannot be undone.')) {
    return;
  }
  
  try {
    const response = await fetch(`/api/v1/keys/${keyId}`, {
      method: 'DELETE'
    });
    
    if (!response.ok) {
      alert('Failed to delete API key');
      return;
    }
    
    loadApiKeys();
  } catch (err) {
    console.error('Failed to delete API key:', err);
    alert('Failed to delete API key: ' + err.message);
  }
}


// ==================== External Backup Storage ====================

let _extBackupSaveTimer = null;

function debounceSaveExternal() {
  clearTimeout(_extBackupSaveTimer);
  _extBackupSaveTimer = setTimeout(saveExternalBackupSettings, 800);
}

function updateExternalBackupType() {
  const type = document.getElementById('ext-backup-type').value;
  document.getElementById('ext-ftp-config').style.display = type === 'ftp' ? '' : 'none';
  document.getElementById('ext-s3-config').style.display = type === 's3' ? '' : 'none';
}

async function loadExternalBackupSettings() {
  try {
    const response = await fetch('/api/settings/external-backup');
    if (!response.ok) return;
    const data = await response.json();

    document.getElementById('ext-backup-enabled').checked = !!data.enabled;
    document.getElementById('ext-backup-config').style.display = data.enabled ? '' : 'none';

    const type = data.type || 'ftp';
    document.getElementById('ext-backup-type').value = type;
    updateExternalBackupType();

    // FTP
    const ftp = data.ftp || {};
    document.getElementById('ext-ftp-host').value = ftp.host || '';
    document.getElementById('ext-ftp-port').value = ftp.port || 21;
    document.getElementById('ext-ftp-username').value = ftp.username || '';
    document.getElementById('ext-ftp-password').value = '';  // never pre-fill passwords
    document.getElementById('ext-ftp-path').value = ftp.remotePath || '/backups/';
    document.getElementById('ext-ftp-passive').checked = ftp.passive !== false;

    // S3
    const s3 = data.s3 || {};
    document.getElementById('ext-s3-bucket').value = s3.bucket || '';
    document.getElementById('ext-s3-region').value = s3.region || 'us-east-1';
    document.getElementById('ext-s3-access-key').value = s3.accessKey || '';
    document.getElementById('ext-s3-secret-key').value = '';  // never pre-fill secrets
    document.getElementById('ext-s3-prefix').value = s3.prefix || 'backups/';
  } catch (err) {
    console.error('Failed to load external backup settings:', err);
  }
}

async function saveExternalBackupSettings() {
  const enabled = document.getElementById('ext-backup-enabled').checked;
  document.getElementById('ext-backup-config').style.display = enabled ? '' : 'none';

  const type = document.getElementById('ext-backup-type').value;

  const payload = {
    enabled,
    type,
    ftp: {
      host: document.getElementById('ext-ftp-host').value,
      port: parseInt(document.getElementById('ext-ftp-port').value) || 21,
      username: document.getElementById('ext-ftp-username').value,
      password: document.getElementById('ext-ftp-password').value,
      remotePath: document.getElementById('ext-ftp-path').value,
      passive: document.getElementById('ext-ftp-passive').checked
    },
    s3: {
      bucket: document.getElementById('ext-s3-bucket').value,
      region: document.getElementById('ext-s3-region').value,
      accessKey: document.getElementById('ext-s3-access-key').value,
      secretKey: document.getElementById('ext-s3-secret-key').value,
      prefix: document.getElementById('ext-s3-prefix').value
    }
  };

  try {
    const response = await fetch('/api/settings/external-backup', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const result = await response.json();
    if (result.success) {
      showNotification('External backup settings saved', 'success');
    }
  } catch (err) {
    console.error('Failed to save external backup settings:', err);
    showNotification('Failed to save external backup settings', 'error');
  }
}

async function testExternalBackupSettings() {
  try {
    showNotification('Testing external backup connection…', 'info');
    const response = await fetch('/api/settings/external-backup/test', { method: 'POST' });
    const result = await response.json();
    if (result.success) {
      showNotification(`✅ Connection successful: ${result.message}`, 'success');
    } else {
      showNotification(`❌ Connection failed: ${result.error}`, 'error');
    }
  } catch (err) {
    showNotification(`❌ Connection failed: ${err.message}`, 'error');
  }
}

// ==================== Notification Preferences (Profile Modal) ====================

async function loadNotificationPrefs() {
  try {
    const resp = await fetch('/api/auth/profile/notifications');
    if (!resp.ok) return;
    const prefs = await resp.json();
    const keys = ['backupComplete', 'backupFailure', 'serverStart', 'serverStop',
                   'playerJoin', 'playerLeave', 'criticalAlerts'];
    for (const key of keys) {
      const el = document.getElementById(`notif-${key}`);
      if (el) el.checked = prefs[key] ?? false;
    }
  } catch (err) {
    console.error('Failed to load notification prefs:', err);
  }
}

async function saveNotificationPrefs(silent = false) {
  const keys = ['backupComplete', 'backupFailure', 'serverStart', 'serverStop',
                 'playerJoin', 'playerLeave', 'criticalAlerts'];
  const prefs = {};
  for (const key of keys) {
    const el = document.getElementById(`notif-${key}`);
    if (el) prefs[key] = el.checked;
  }
  try {
    const resp = await fetch('/api/auth/profile/notifications', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(prefs)
    });
    if (resp.ok) {
      if (!silent) showNotification('Notification preferences saved', 'success');
      return true;
    } else {
      const d = await resp.json();
      showNotification(d.error || 'Failed to save notification preferences', 'error');
      return false;
    }
  } catch (err) {
    showNotification('Failed to save notification preferences', 'error');
    return false;
  }
}

// ==================== Webhook Settings ====================

let _webhookSaveTimer = null;
function debounceWebhookSave() {
  clearTimeout(_webhookSaveTimer);
  _webhookSaveTimer = setTimeout(saveWebhookSettings, 800);
}

function toggleWebhookFields() {
  const enabled = document.getElementById('webhook-enabled').checked;
  const section = document.getElementById('webhook-config-section');
  if (section) section.style.display = enabled ? 'block' : 'none';
}

async function loadWebhookSettings() {
  try {
    const resp = await fetch('/api/settings/webhook');
    if (!resp.ok) return;
    const s = await resp.json();
    document.getElementById('webhook-enabled').checked = s.enabled ?? false;
    document.getElementById('webhook-url').value = s.url ?? '';
    document.getElementById('webhook-secret').value = '';
    document.getElementById('webhook-secret').placeholder = s.url ? '••••••••' : 'Optional HMAC secret';
    toggleWebhookFields();
  } catch (err) {
    console.error('Failed to load webhook settings:', err);
  }
}

async function saveWebhookSettings() {
  const settings = {
    enabled: document.getElementById('webhook-enabled').checked,
    url: document.getElementById('webhook-url').value.trim(),
  };
  const secret = document.getElementById('webhook-secret').value;
  if (secret) settings.secret = secret;

  try {
    const resp = await fetch('/api/settings/webhook', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings)
    });
    const d = await resp.json();
    if (d.success) {
      showNotification('Webhook settings saved', 'success');
      document.getElementById('webhook-secret').value = '';
      document.getElementById('webhook-secret').placeholder = settings.url ? '••••••••' : 'Optional HMAC secret';
    } else {
      showNotification(d.error || 'Failed to save webhook settings', 'error');
    }
  } catch (err) {
    showNotification('Failed to save webhook settings', 'error');
  }
}

async function testWebhookSettings() {
  try {
    showNotification('Sending test webhook…', 'info');
    const resp = await fetch('/api/settings/webhook/test', { method: 'POST' });
    const d = await resp.json();
    if (d.success) {
      showNotification(`✅ Webhook delivered: ${d.message}`, 'success');
    } else {
      showNotification(`❌ Webhook failed: ${d.error}`, 'error');
    }
  } catch (err) {
    showNotification(`❌ Webhook test failed: ${err.message}`, 'error');
  }
}

// ==================== Email Templates ====================

const _TEMPLATE_LABELS = {
  backup_complete: { label: 'Backup Completed', vars: 'serverName, backupName, size, timestamp, siteTitle' },
  backup_failure:  { label: 'Backup Failed',    vars: 'serverName, error, timestamp, siteTitle' },
  server_start:    { label: 'Server Started',   vars: 'serverName, serverId, timestamp, siteTitle' },
  server_stop:     { label: 'Server Stopped',   vars: 'serverName, serverId, timestamp, siteTitle' },
  player_join:     { label: 'Player Joined',    vars: 'player, serverName, serverId, timestamp, siteTitle' },
  player_leave:    { label: 'Player Left',      vars: 'player, serverName, serverId, timestamp, siteTitle' },
  critical_alert:  { label: 'Critical Alert',   vars: 'alertType, details, timestamp, siteTitle' },
};

let _emailTemplates = {};

async function loadEmailTemplates() {
  try {
    const resp = await fetch('/api/settings/email-templates');
    if (!resp.ok) return;
    _emailTemplates = await resp.json();
    renderEmailTemplates();
  } catch (err) {
    console.error('Failed to load email templates:', err);
  }
}

function renderEmailTemplates() {
  const container = document.getElementById('email-templates-container');
  if (!container) return;

  const entries = Object.entries(_TEMPLATE_LABELS);
  container.innerHTML = entries.map(([key, meta]) => {
    const tmpl = _emailTemplates[key] || {};
    return `
      <div class="email-tmpl-accordion" id="tmpl-block-${key}">
        <div class="email-tmpl-header" onclick="toggleTemplateEditor('${key}')">
          <span class="email-tmpl-name">${meta.label}</span>
          <small class="email-tmpl-vars">Variables: <code>${meta.vars}</code></small>
          <span class="email-tmpl-chevron" id="tmpl-chevron-${key}">▼</span>
        </div>
        <div class="email-tmpl-body" id="tmpl-body-${key}" style="display:none;">
          <div class="form-group">
            <label for="tmpl-subject-${key}">Subject</label>
            <input type="text" id="tmpl-subject-${key}" class="form-control"
                   value="${escapeAttrValue(tmpl.subject || '')}" placeholder="Subject template…">
          </div>
          <div class="form-group">
            <label for="tmpl-html-${key}">HTML Body</label>
            <textarea id="tmpl-html-${key}" class="form-control tmpl-textarea"
                      rows="8" placeholder="HTML body template…">${escapeHtml(tmpl.html || '')}</textarea>
          </div>
          <div class="form-group">
            <label for="tmpl-text-${key}">Plain-text Body <span class="optional-label">(Optional)</span></label>
            <textarea id="tmpl-text-${key}" class="form-control tmpl-textarea"
                      rows="3" placeholder="Plain text fallback…">${escapeHtml(tmpl.text || '')}</textarea>
          </div>
          <div class="smtp-actions">
            <button type="button" class="btn btn-primary btn-small" onclick="saveEmailTemplate('${key}')">💾 Save</button>
            <button type="button" class="btn btn-secondary btn-small" onclick="resetEmailTemplate('${key}')">↩ Reset to Default</button>
          </div>
        </div>
      </div>`;
  }).join('');
}

function toggleTemplateEditor(key) {
  const body = document.getElementById(`tmpl-body-${key}`);
  const chevron = document.getElementById(`tmpl-chevron-${key}`);
  if (!body) return;
  const isOpen = body.style.display !== 'none';
  body.style.display = isOpen ? 'none' : 'block';
  if (chevron) chevron.textContent = isOpen ? '▼' : '▲';
}

async function saveEmailTemplate(key) {
  const subject = document.getElementById(`tmpl-subject-${key}`)?.value || '';
  const html    = document.getElementById(`tmpl-html-${key}`)?.value || '';
  const text    = document.getElementById(`tmpl-text-${key}`)?.value || '';

  try {
    const resp = await fetch(`/api/settings/email-template/${key}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subject, html, text })
    });
    const d = await resp.json();
    if (d.success) {
      showNotification(`Template "${_TEMPLATE_LABELS[key]?.label}" saved`, 'success');
      _emailTemplates[key] = { subject, html, text };
    } else {
      showNotification(d.error || 'Failed to save template', 'error');
    }
  } catch (err) {
    showNotification('Failed to save template', 'error');
  }
}

async function resetEmailTemplate(key) {
  const confirmed = await confirmAction(
    `Reset the "${_TEMPLATE_LABELS[key]?.label}" template to its built-in default?`
  );
  if (!confirmed) return;
  try {
    await fetch(`/api/settings/email-template/${key}/reset`, { method: 'POST' });
    showNotification('Template reset to default', 'success');
    await loadEmailTemplates();
  } catch (err) {
    showNotification('Failed to reset template', 'error');
  }
}


// ==================== Action Policies ====================

const POLICY_DEFS = [
  { key: 'registration',     label: 'User Registration',    desc: 'New user account sign-ups' },
  { key: 'serverCreate',     label: 'Server Creation',      desc: 'Creating new game servers' },
  { key: 'serverDelete',     label: 'Server Deletion',      desc: 'Deleting game servers' },
  { key: 'serverEdit',       label: 'Server Settings',      desc: 'Editing server configuration and properties' },
  { key: 'serverLifecycle',  label: 'Server Start/Stop',    desc: 'Starting, stopping, and restarting servers' },
  { key: 'backupCreate',     label: 'Backup Creation',      desc: 'Creating server backups' },
  { key: 'backupDelete',     label: 'Backup Deletion',      desc: 'Deleting server backups' },
  { key: 'fileUpload',       label: 'File Uploads',         desc: 'Uploading files to server directories' },
  { key: 'modManagement',    label: 'Mod Management',       desc: 'Installing, enabling, disabling, or deleting mods/plugins' },
  { key: 'playerManagement', label: 'Player Management',    desc: 'Whitelist, ban, op, and kick operations' },
];

let _currentPolicies = {};

async function loadPolicies() {
  try {
    const resp = await fetch('/api/settings/policies');
    if (!resp.ok) return;
    const data = await resp.json();
    _currentPolicies = data.policies || {};
    renderPolicies();
  } catch (err) {
    console.error('Failed to load policies:', err);
  }
}

function renderPolicies() {
  const container = document.getElementById('policy-list');
  if (!container) return;

  container.innerHTML = POLICY_DEFS.map(p => {
    const current = _currentPolicies[p.key] || 'allow';
    return `<div class="policy-row">
      <div class="policy-info">
        <label>${escapeHtml(p.label)}</label>
        <small>${escapeHtml(p.desc)}</small>
      </div>
      <div class="policy-selector" data-key="${p.key}">
        <button type="button" class="${current === 'allow' ? 'active' : ''}"
          onclick="setPolicy('${p.key}', 'allow', this)">Allow</button>
        <button type="button" class="${current === 'notify' ? 'active-warn' : ''}"
          onclick="setPolicy('${p.key}', 'notify', this)">Notify</button>
        <button type="button" class="${current === 'require_approval' ? 'active-danger' : ''}"
          onclick="setPolicy('${p.key}', 'require_approval', this)">Require Approval</button>
      </div>
    </div>`;
  }).join('');
}

async function setPolicy(key, value, btnEl) {
  _currentPolicies[key] = value;

  // Update button states in this selector
  const selector = btnEl.parentElement;
  selector.querySelectorAll('button').forEach(b => {
    b.className = '';
  });
  if (value === 'allow') btnEl.className = 'active';
  else if (value === 'notify') btnEl.className = 'active-warn';
  else btnEl.className = 'active-danger';

  try {
    const resp = await fetch('/api/settings/policies', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ [key]: value })
    });
    if (!resp.ok) throw new Error('Save failed');
  } catch (err) {
    console.error('Failed to save policy:', err);
    showNotification('Failed to save policy', 'error');
  }
}


// ==================== Pending Actions (Approvals tab) ====================

async function loadPendingActions() {
  try {
    const resp = await fetch('/api/admin/pending-actions');
    if (!resp.ok) {
      document.getElementById('pending-actions-count').textContent = '0';
      return;
    }
    const data = await resp.json();
    const actions = data.actions || [];

    document.getElementById('pending-actions-count').textContent = actions.length;

    const list = document.getElementById('pending-actions-list');
    if (actions.length === 0) {
      list.innerHTML = `<div class="approval-empty"><p>No pending action requests</p></div>`;
      return;
    }

    list.innerHTML = `<div class="approval-items">
      ${actions.map(a => {
        const payloadPreview = Object.entries(a.payload || {})
          .filter(([k]) => k !== 'serverName')
          .map(([k, v]) => `${escapeHtml(k)}: ${escapeHtml(String(v))}`)
          .join('\n');
        return `<div class="pending-action-item">
          <div class="pending-action-header">
            <span class="pending-action-label">${escapeHtml(a.actionLabel || a.actionType)}</span>
          </div>
          <div class="pending-action-meta">
            Requested by <strong>${escapeHtml(a.username || 'Unknown')}</strong>
            ${a.payload?.serverName ? ` for server <strong>${escapeHtml(a.payload.serverName)}</strong>` : ''}
            &mdash; ${new Date(a.created).toLocaleString()}
          </div>
          ${payloadPreview ? `<div class="pending-action-details">${escapeHtml(payloadPreview)}</div>` : ''}
          <div class="pending-action-actions">
            <button class="btn btn-small btn-success" onclick="approvePendingAction('${a.id}')">Approve</button>
            <button class="btn btn-small btn-danger" onclick="rejectPendingAction('${a.id}')">Reject</button>
          </div>
        </div>`;
      }).join('')}
    </div>`;
  } catch (err) {
    console.error('Failed to load pending actions:', err);
    document.getElementById('pending-actions-count').textContent = '0';
    document.getElementById('pending-actions-list').innerHTML = `<div class="approval-empty"><p>Error loading pending actions</p></div>`;
  }
}

async function approvePendingAction(actionId) {
  try {
    const resp = await fetch(`/api/admin/pending-actions/${actionId}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    if (!resp.ok) throw new Error('Failed to approve');
    showNotification('Action approved and executed', 'success');
    loadPendingActions();
  } catch (err) {
    console.error('Failed to approve action:', err);
    alert('Failed to approve action: ' + err.message);
  }
}

async function rejectPendingAction(actionId) {
  const note = prompt('Rejection reason (optional):') || '';
  try {
    const resp = await fetch(`/api/admin/pending-actions/${actionId}/reject`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note })
    });
    if (!resp.ok) throw new Error('Failed to reject');
    showNotification('Action rejected', 'success');
    loadPendingActions();
  } catch (err) {
    console.error('Failed to reject action:', err);
    alert('Failed to reject action: ' + err.message);
  }
}


// ==================== Group Management ====================

let _groupsCache = [];
let _permCatalog = null;

async function populateGroupSelect(selectId, selectedId) {
  if (!_groupsCache.length) {
    try {
      const resp = await fetch('/api/admin/groups');
      if (resp.ok) {
        const data = await resp.json();
        _groupsCache = data.groups || [];
      }
    } catch (e) { /* ignore */ }
  }
  const sel = document.getElementById(selectId);
  if (!sel) return;
  sel.innerHTML = _groupsCache.map(g =>
    `<option value="${escapeAttrValue(g.id)}" ${g.id === selectedId ? 'selected' : ''}>${escapeHtml(g.name)}</option>`
  ).join('');
}

async function loadGroups() {
  const container = document.getElementById('groups-list');
  if (!container) return;
  try {
    const resp = await fetch('/api/admin/groups');
    if (!resp.ok) return;
    const data = await resp.json();
    _groupsCache = data.groups || [];
    renderGroups(_groupsCache, container);
  } catch (e) {
    container.innerHTML = '<div class="jobs-empty">Failed to load groups.</div>';
  }
}

function renderGroups(groups, container) {
  if (!groups.length) {
    container.innerHTML = '<div class="jobs-empty">No groups found.</div>';
    return;
  }
  container.innerHTML = groups.map(g => {
    const permCount = g.permissions.includes('*') ? 'All' : g.permissions.length;
    const badges = [
      g.isBuiltin ? '<span class="badge badge-secondary">Built-in</span>' : '',
      g.isDefault ? '<span class="badge badge-success">Default</span>' : '',
    ].filter(Boolean).join(' ');
    return `<div class="group-card">
      <div class="group-card-header">
        <span class="group-badge">${escapeHtml(g.name)}</span>
        ${badges}
        <span class="text-muted" style="margin-left:auto">${permCount} permissions | ${g.userCount || 0} users</span>
      </div>
      <div class="group-card-actions">
        <button class="btn btn-small btn-primary" onclick="openEditGroupModal('${escapeAttr(g.id)}')">Edit</button>
        ${!g.isBuiltin ? `<button class="btn btn-small btn-danger" onclick="deleteGroup('${escapeAttr(g.id)}', '${escapeAttr(g.name)}')">Delete</button>` : ''}
        ${!g.isDefault ? `<button class="btn btn-small" onclick="setDefaultGroup('${escapeAttr(g.id)}')">Set Default</button>` : ''}
      </div>
    </div>`;
  }).join('');
}

async function loadPermCatalog() {
  if (_permCatalog) return _permCatalog;
  try {
    const resp = await fetch('/api/admin/groups/permissions');
    if (resp.ok) _permCatalog = await resp.json();
  } catch (e) { /* ignore */ }
  return _permCatalog;
}

function renderPermissionCheckboxes(containerId, selectedPerms) {
  const catalog = _permCatalog;
  if (!catalog) return;
  const container = document.getElementById(containerId);
  if (!container) return;
  const isAll = selectedPerms.includes('*');
  let html = '';
  for (const [category, perms] of Object.entries(catalog.categories)) {
    html += `<div class="perm-category">
      <div class="perm-category-header">
        <strong>${escapeHtml(category)}</strong>
        <button type="button" class="btn btn-small" onclick="toggleAllPerms('${containerId}', '${escapeAttr(category)}', true)">Select All</button>
        <button type="button" class="btn btn-small" onclick="toggleAllPerms('${containerId}', '${escapeAttr(category)}', false)">Deselect All</button>
      </div>
      <div class="perm-grid">`;
    for (const p of perms) {
      const label = catalog.labels[p] || p;
      const checked = isAll || selectedPerms.includes(p) ? 'checked' : '';
      html += `<label class="perm-checkbox" data-category="${escapeAttrValue(category)}">
        <input type="checkbox" name="perm" value="${escapeAttrValue(p)}" ${checked}> ${escapeHtml(label)}
      </label>`;
    }
    html += '</div></div>';
  }
  container.innerHTML = html;
}

function toggleAllPerms(containerId, category, state) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.querySelectorAll(`label[data-category="${category}"] input`).forEach(cb => {
    cb.checked = state;
  });
}

function getSelectedPerms(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return [];
  return Array.from(container.querySelectorAll('input[name="perm"]:checked')).map(cb => cb.value);
}

async function openAddGroupModal() {
  await loadPermCatalog();
  document.getElementById('group-modal-title').textContent = 'Create Group';
  document.getElementById('group-name').value = '';
  document.getElementById('group-name').disabled = false;
  document.getElementById('group-default').checked = false;
  renderPermissionCheckboxes('group-perms', []);
  document.getElementById('group-modal').style.display = 'flex';
  document.getElementById('group-modal').dataset.groupId = '';
}

async function openEditGroupModal(groupId) {
  await loadPermCatalog();
  const group = _groupsCache.find(g => g.id === groupId);
  if (!group) return;
  document.getElementById('group-modal-title').textContent = 'Edit Group: ' + group.name;
  document.getElementById('group-name').value = group.name;
  document.getElementById('group-name').disabled = group.isBuiltin;
  document.getElementById('group-default').checked = group.isDefault;
  renderPermissionCheckboxes('group-perms', group.permissions);
  document.getElementById('group-modal').style.display = 'flex';
  document.getElementById('group-modal').dataset.groupId = groupId;
}

function closeGroupModal() {
  document.getElementById('group-modal').style.display = 'none';
}

async function saveGroup() {
  const groupId = document.getElementById('group-modal').dataset.groupId;
  const name = document.getElementById('group-name').value.trim();
  const isDefault = document.getElementById('group-default').checked;
  const permissions = getSelectedPerms('group-perms');

  if (!name) {
    alert('Group name is required');
    return;
  }

  try {
    const url = groupId ? `/api/admin/groups/${groupId}` : '/api/admin/groups';
    const method = groupId ? 'PUT' : 'POST';
    const body = { permissions, isDefault };
    if (!groupId || !document.getElementById('group-name').disabled) {
      body.name = name;
    }
    const resp = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Failed to save group');
    showNotification(groupId ? 'Group updated' : 'Group created', 'success');
    closeGroupModal();
    _groupsCache = [];
    loadGroups();
  } catch (err) {
    alert('Failed to save group: ' + err.message);
  }
}

async function deleteGroup(groupId, name) {
  if (!confirm(`Delete group "${name}"? Users in this group will be moved to the default group.`)) return;
  try {
    const resp = await fetch(`/api/admin/groups/${groupId}`, { method: 'DELETE' });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Failed to delete');
    showNotification('Group deleted', 'success');
    _groupsCache = [];
    loadGroups();
    loadUsers();
  } catch (err) {
    alert('Failed to delete group: ' + err.message);
  }
}

async function setDefaultGroup(groupId) {
  try {
    const resp = await fetch(`/api/admin/groups/${groupId}/default`, { method: 'POST' });
    if (!resp.ok) throw new Error('Failed');
    showNotification('Default group updated', 'success');
    _groupsCache = [];
    loadGroups();
  } catch (err) {
    alert('Failed to set default group: ' + err.message);
  }
}
