/**
 * auth.js – Handles login & register form logic on login.html
 */

// ── Tab switching ─────────────────────────────────────────────────────────────
document.querySelectorAll('.auth-tab').forEach(tab => {
  tab.addEventListener('click', () => switchForm(tab.dataset.form));
});
document.querySelectorAll('[data-switch]').forEach(link => {
  link.addEventListener('click', e => { e.preventDefault(); switchForm(link.dataset.switch); });
});

function switchForm(name) {
  document.querySelectorAll('.auth-tab').forEach(t  => t.classList.toggle('active', t.dataset.form === name));
  document.querySelectorAll('.auth-form').forEach(f => f.classList.toggle('active', f.id === name + 'Form'));
  clearErrors();
}

// ── Password visibility toggles ───────────────────────────────────────────────
document.querySelectorAll('.toggle-pw').forEach(btn => {
  btn.addEventListener('click', () => {
    const input = document.getElementById(btn.dataset.target);
    input.type  = input.type === 'password' ? 'text' : 'password';
    btn.textContent = input.type === 'password' ? '👁' : '🙈';
  });
});

// ── Check if already logged in ────────────────────────────────────────────────
(async () => {
  try {
    const res  = await fetch('/api/auth/me');
    const data = await res.json();
    if (data.loggedIn) window.location.replace('/index.html');
  } catch { /* ignore */ }
})();

// ── Login ─────────────────────────────────────────────────────────────────────
document.getElementById('loginForm').addEventListener('submit', async e => {
  e.preventDefault();
  const btn      = document.getElementById('loginBtn');
  const username = document.getElementById('loginUsername').value.trim();
  const password = document.getElementById('loginPassword').value;

  if (!username || !password) return showError('loginError', 'Please fill in all fields.');

  setBusy(btn, true);
  clearErrors();

  try {
    const res  = await fetch('/api/auth/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username, password })
    });
    const data = await res.json();

    if (!res.ok) return showError('loginError', data.error || 'Login failed.');
    window.location.replace('/index.html');

  } catch {
    showError('loginError', 'Network error. Please try again.');
  } finally {
    setBusy(btn, false);
  }
});

// ── Register ──────────────────────────────────────────────────────────────────
document.getElementById('registerForm').addEventListener('submit', async e => {
  e.preventDefault();
  const btn      = document.getElementById('registerBtn');
  const fullname = document.getElementById('regFullname').value.trim();
  const username = document.getElementById('regUsername').value.trim();
  const password = document.getElementById('regPassword').value;
  const confirm  = document.getElementById('regConfirm').value;

  if (!fullname || !username || !password || !confirm)
    return showError('registerError', 'Please fill in all fields.');

  if (password !== confirm)
    return showError('registerError', 'Passwords do not match.');

  if (password.length < 6)
    return showError('registerError', 'Password must be at least 6 characters.');

  setBusy(btn, true);
  clearErrors();

  try {
    const res  = await fetch('/api/auth/register', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ fullname, username, password })
    });
    const data = await res.json();

    if (!res.ok) return showError('registerError', data.error || 'Registration failed.');
    window.location.replace('/index.html');

  } catch {
    showError('registerError', 'Network error. Please try again.');
  } finally {
    setBusy(btn, false);
  }
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function showError(id, msg) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.classList.remove('hidden');
}
function clearErrors() {
  document.querySelectorAll('.auth-error').forEach(e => e.classList.add('hidden'));
}
function setBusy(btn, busy) {
  btn.disabled = busy;
  btn.querySelector('.btn-text').textContent   = busy ? 'Please wait…' : btn.id === 'loginBtn' ? 'Sign In' : 'Create Account';
}
