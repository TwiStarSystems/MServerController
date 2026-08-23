// First-run setup page — create the initial administrator account.
// The /api/setup/admin endpoint is CSRF-exempt (like login) and hard-gated
// server-side by needs_setup(), so this page only needs a plain fetch.

function showError(msg) {
  const el = document.getElementById('error-message');
  const ok = document.getElementById('success-message');
  if (ok) ok.style.display = 'none';
  if (el) { el.textContent = msg; el.style.display = 'block'; }
}

function showSuccess(msg) {
  const el = document.getElementById('error-message');
  const ok = document.getElementById('success-message');
  if (el) el.style.display = 'none';
  if (ok) { ok.textContent = msg; ok.style.display = 'block'; }
}

document.addEventListener('DOMContentLoaded', async () => {
  // If setup is already done (e.g. the page was left open), bounce to login.
  try {
    const res = await fetch('/api/setup/status');
    const data = await res.json();
    if (!data.needsSetup) {
      window.location.href = '/login.html';
      return;
    }
  } catch (e) {
    // Non-fatal: let the form submit surface any error.
  }

  const form = document.getElementById('setup-form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('setup-username').value.trim();
    const name = document.getElementById('setup-name').value.trim();
    const email = document.getElementById('setup-email').value.trim();
    const password = document.getElementById('setup-password').value;
    const confirm = document.getElementById('setup-confirm').value;

    if (password !== confirm) {
      showError('Passwords do not match.');
      return;
    }

    const passwordError = validatePassword(password);
    if (passwordError) {
      showError(passwordError + '.');
      return;
    }

    const btn = form.querySelector('button[type="submit"]');
    btn.disabled = true;
    const originalText = btn.textContent;
    btn.textContent = 'Creating…';

    try {
      const res = await fetch('/api/setup/admin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, name, email, password })
      });
      const data = await res.json().catch(() => ({}));

      if (res.ok && data.success) {
        showSuccess('Admin account created. Redirecting to login…');
        setTimeout(() => { window.location.href = '/login.html'; }, 1500);
      } else {
        showError(data.error || 'Failed to create admin account.');
        btn.disabled = false;
        btn.textContent = originalText;
      }
    } catch (err) {
      showError('Network error: ' + err.message);
      btn.disabled = false;
      btn.textContent = originalText;
    }
  });
});
