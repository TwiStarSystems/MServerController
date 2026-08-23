// Login page JavaScript

// Note: CSRF token management is in utils.js (window.csrfToken and fetchCSRFToken)

// Prevent multiple auth checks
let authCheckDone = false;

/**
 * POST helper that auto-refreshes the CSRF token on 403 and retries once.
 */
async function csrfPost(url, payload) {
    const makeRequest = () => fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.csrfToken },
        body: JSON.stringify(payload)
    });

    let response = await makeRequest();

    if (response.status === 403) {
        const data = await response.clone().json().catch(() => ({}));
        if (data.error && data.error.includes('CSRF')) {
            await fetchCSRFToken();
            response = await makeRequest();
        }
    }

    return response;
}

document.addEventListener('DOMContentLoaded', async () => {
    // Fetch CSRF token first
    await fetchCSRFToken();
    
    // Check if already logged in (only once)
    if (!authCheckDone) {
        authCheckDone = true;
        checkAuthStatus();
    }
    
    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.dataset.tab;
            
            // Update active tab button
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            // Show corresponding content
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.getElementById(`${tab}-tab`).classList.add('active');
            
            // Clear messages
            hideMessages();
        });
    });
    
    // Login form
    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        hideMessages();
        
        const username = document.getElementById('login-username').value.trim();
        const password = document.getElementById('login-password').value;
        const submitBtn = e.target.querySelector('button[type="submit"]');
        
        submitBtn.disabled = true;
        submitBtn.textContent = 'Signing in...';
        
        try {
            const response = await csrfPost('/api/auth/login', { username, password });
            
            const data = await response.json();
            
            if (response.ok) {
                if (data.mfaRequired) {
                    // Show MFA verification modal/screen
                    showMFAVerification();
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Sign In';
                } else if (data.mfaSetupRequired) {
                    // MFA is mandatory for this account but not yet set up — force enrollment now.
                    showMFAEnrollment();
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Sign In';
                } else {
                    showSuccess('Login successful! Redirecting...');
                    setTimeout(() => {
                        window.location.href = '/';
                    }, 1000);
                }
            } else {
                showError(data.error || 'Login failed');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Sign In';
            }
        } catch (err) {
            showError('Network error. Please try again.');
            submitBtn.disabled = false;
            submitBtn.textContent = 'Sign In';
        }
    });
    
    // Register form
    document.getElementById('register-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        hideMessages();
        
        const username = document.getElementById('register-username').value.trim();
        const password = document.getElementById('register-password').value;
        const confirm = document.getElementById('register-confirm').value;
        const submitBtn = e.target.querySelector('button[type="submit"]');
        
        // Validate password match
        if (password !== confirm) {
            showError('Passwords do not match');
            return;
        }
        
        // Validate username
        if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
            showError('Username can only contain letters, numbers, underscores, and hyphens');
            return;
        }

        // Validate password against the server's policy
        const passwordError = validatePassword(password);
        if (passwordError) {
            showError(passwordError);
            return;
        }
        
        submitBtn.disabled = true;
        submitBtn.textContent = 'Creating account...';
        
        try {
            const response = await csrfPost('/api/auth/register', { username, password });
            
            const data = await response.json();
            
            if (response.ok) {
                showSuccess('Account created! Please wait for admin approval before logging in.');
                document.getElementById('register-form').reset();
                
                // Switch to login tab after 2 seconds
                setTimeout(() => {
                    document.querySelector('[data-tab="login"]').click();
                }, 2000);
            } else {
                showError(data.error || 'Registration failed');
            }
        } catch (err) {
            showError('Network error. Please try again.');
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Create Account';
        }
    });
});

async function checkAuthStatus() {
    try {
        const response = await fetch('/api/auth/me');
        if (response.ok) {
            const data = await response.json();
            if (data && data.username) {
                // Already logged in, redirect to main app
                window.location.replace('/');
            }
        }
        // If not ok (401, etc.), just stay on login page - no action needed
    } catch (err) {
        // Network error - stay on login page, don't do anything
        console.log('Auth check failed, staying on login page');
    }
}

function showError(message) {
    const el = document.getElementById('error-message');
    el.textContent = message;
    el.classList.add('show');
}

function showSuccess(message) {
    const el = document.getElementById('success-message');
    el.textContent = message;
    el.classList.add('show');
}

function hideMessages() {
    document.getElementById('error-message').classList.remove('show');
    document.getElementById('success-message').classList.remove('show');
}

// ==================== MFA Verification ====================

// Hide the base login UI (tabs + login/register forms + messages) so a full-card
// MFA screen can take over. There is no single wrapper element to toggle, so hide
// the pieces that actually exist.
function hideLoginBase() {
    document.querySelectorAll('.tabs, .tab-content').forEach(el => { el.style.display = 'none'; });
    hideMessages();
}

function showMFAVerification() {
    // Hide login/register forms
    hideLoginBase();

    // Create MFA verification UI
    const mfaContainer = document.createElement('div');
    mfaContainer.id = 'mfa-container';
    mfaContainer.className = 'auth-container';
    mfaContainer.innerHTML = `
        <div class="auth-card">
            <h1>🔐 Two-Factor Authentication</h1>
            <p class="auth-subtitle">Enter the 6-digit code from your authenticator app</p>
            
            <div id="mfa-error-message" class="error-message"></div>
            
            <form id="mfa-verify-form">
                <div class="form-group">
                    <label for="mfa-code">Verification Code</label>
                    <input type="text" id="mfa-code" placeholder="123456" maxlength="6" pattern="[0-9]{6}" required autofocus>
                </div>
                
                <button type="submit" class="btn-primary">Verify</button>
                
                <div class="mfa-recovery-link">
                    <a href="#" onclick="showMFARecoveryInput(); return false;">Lost your authenticator? Use recovery code</a>
                </div>
                
                <div id="mfa-recovery-container" style="display: none;">
                    <div class="form-group">
                        <label for="mfa-recovery">Recovery Code</label>
                        <input type="text" id="mfa-recovery" placeholder="XXXXXXXX-XXXXXXXX-XXXXXXXX">
                        <small class="form-hint">Using your recovery code will disable MFA on your account.</small>
                    </div>
                    <button type="button" class="btn-secondary" onclick="verifyMFARecovery()">Use Recovery Code</button>
                </div>
                
                <button type="button" class="btn-text" onclick="cancelMFAVerification()">Back to Login</button>
            </form>
        </div>
    `;
    
    document.querySelector('.login-container').appendChild(mfaContainer);
    
    // Handle MFA form submission
    document.getElementById('mfa-verify-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        await verifyMFACode();
    });
}

function showMFARecoveryInput() {
    document.getElementById('mfa-recovery-container').style.display = 'block';
}

async function verifyMFACode() {
    const code = document.getElementById('mfa-code').value.trim();
    const submitBtn = document.querySelector('#mfa-verify-form button[type="submit"]');
    
    if (!code || code.length !== 6) {
        showMFAError('Please enter a 6-digit code');
        return;
    }
    
    submitBtn.disabled = true;
    submitBtn.textContent = 'Verifying...';
    
    try {
        const response = await csrfPost('/api/auth/mfa/verify-login', { code, useRecovery: false });
        
        const data = await response.json();
        
        if (response.ok) {
            showSuccess('Login successful! Redirecting...');
            setTimeout(() => {
                window.location.href = '/';
            }, 1000);
        } else {
            showMFAError(data.error || 'Invalid verification code');
            submitBtn.disabled = false;
            submitBtn.textContent = 'Verify';
        }
    } catch (err) {
        showMFAError('Network error. Please try again.');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Verify';
    }
}

async function verifyMFARecovery() {
    const code = document.getElementById('mfa-recovery').value.trim();
    
    if (!code) {
        showMFAError('Please enter your recovery code');
        return;
    }
    
    try {
        const response = await csrfPost('/api/auth/mfa/verify-login', { code, useRecovery: true });
        
        const data = await response.json();
        
        if (response.ok) {
            showSuccess('Login successful! MFA has been disabled. Redirecting...');
            setTimeout(() => {
                window.location.href = '/';
            }, 1500);
        } else {
            showMFAError(data.error || 'Invalid recovery code');
        }
    } catch (err) {
        showMFAError('Network error. Please try again.');
    }
}

function showMFAError(message) {
    const el = document.getElementById('mfa-error-message');
    el.textContent = message;
    el.style.display = 'block';
}

function cancelMFAVerification() {
    // Simplest reliable reset back to the login form.
    window.location.reload();
}

// ==================== Forced MFA Enrollment ====================

async function showMFAEnrollment() {
    // Hide login/register forms
    hideLoginBase();

    const enrollContainer = document.createElement('div');
    enrollContainer.id = 'mfa-enroll-container';
    enrollContainer.className = 'auth-container';
    enrollContainer.innerHTML = `
        <div class="auth-card">
            <h1>🔐 Set Up Two-Factor Authentication</h1>
            <p class="auth-subtitle">Your administrator requires MFA on this account. Scan the QR code with your authenticator app, then enter the 6-digit code to finish.</p>

            <div id="mfa-enroll-error" class="error-message"></div>

            <div id="mfa-enroll-loading" style="text-align:center;">Generating your secret…</div>

            <div id="mfa-enroll-body" style="display:none;">
                <div style="text-align:center; margin: 10px 0;">
                    <img id="mfa-enroll-qr" alt="MFA QR code" style="max-width:200px; background:#fff; padding:8px; border-radius:8px;">
                </div>
                <div class="form-group">
                    <label>Can't scan? Enter this key manually</label>
                    <input type="text" id="mfa-enroll-secret" readonly>
                </div>
                <form id="mfa-enroll-form">
                    <div class="form-group">
                        <label for="mfa-enroll-code">Verification Code</label>
                        <input type="text" id="mfa-enroll-code" placeholder="123456" maxlength="6" pattern="[0-9]{6}" required autofocus>
                    </div>
                    <button type="submit" class="btn-primary">Enable MFA &amp; Continue</button>
                </form>

                <div id="mfa-enroll-recovery" style="display:none; margin-top:15px;">
                    <div class="error-message show" style="background:#16213e;">
                        <strong>Save your recovery code</strong><br>
                        <code id="mfa-enroll-recovery-code" style="font-size:14px;"></code><br>
                        <small>Store it somewhere safe — it lets you regain access if you lose your authenticator.</small>
                    </div>
                    <button type="button" class="btn-primary" onclick="window.location.href='/'">I've saved it — Continue</button>
                </div>
            </div>

            <button type="button" class="btn-text" onclick="window.location.reload()">Back to Login</button>
        </div>
    `;
    document.querySelector('.login-container').appendChild(enrollContainer);

    document.getElementById('mfa-enroll-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        await verifyMFAEnrollment();
    });

    // Kick off secret/QR generation
    try {
        const response = await csrfPost('/api/auth/mfa/enroll/setup', {});
        const data = await response.json();
        if (response.ok) {
            document.getElementById('mfa-enroll-qr').src = data.qrCode;
            document.getElementById('mfa-enroll-secret').value = data.manualEntry;
            window._mfaEnrollSecret = data.secret;
            document.getElementById('mfa-enroll-loading').style.display = 'none';
            document.getElementById('mfa-enroll-body').style.display = 'block';
        } else {
            showMFAEnrollError(data.error || 'Failed to start MFA setup');
        }
    } catch (err) {
        showMFAEnrollError('Network error. Please try again.');
    }
}

async function verifyMFAEnrollment() {
    const code = document.getElementById('mfa-enroll-code').value.trim();
    const submitBtn = document.querySelector('#mfa-enroll-form button[type="submit"]');

    if (!code || code.length !== 6) {
        showMFAEnrollError('Please enter a 6-digit code');
        return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = 'Verifying...';

    try {
        const response = await csrfPost('/api/auth/mfa/enroll/verify', {
            secret: window._mfaEnrollSecret,
            code
        });
        const data = await response.json();

        if (response.ok) {
            // Show the recovery code and require acknowledgement before entering the app.
            document.getElementById('mfa-enroll-form').style.display = 'none';
            document.getElementById('mfa-enroll-recovery-code').textContent = data.recoveryCode;
            document.getElementById('mfa-enroll-recovery').style.display = 'block';
        } else {
            showMFAEnrollError(data.error || 'Invalid verification code');
            submitBtn.disabled = false;
            submitBtn.textContent = 'Enable MFA & Continue';
        }
    } catch (err) {
        showMFAEnrollError('Network error. Please try again.');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Enable MFA & Continue';
    }
}

function showMFAEnrollError(message) {
    const el = document.getElementById('mfa-enroll-error');
    el.textContent = message;
    el.classList.add('show');
    el.style.display = 'block';
}
