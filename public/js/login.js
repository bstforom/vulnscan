// public/js/login.js
const $ = (s) => document.querySelector(s);
let mode = 'login';

// If already signed in, go to the dashboard
fetch('/api/auth/me').then((r) => { if (r.ok) location.href = '/'; }).catch(() => {});

// Hide the registration tab if registration is closed
fetch('/api/auth/config').then((r) => r.json()).then((c) => {
  if (!c.allowRegistration) $('#tab-register').style.display = 'none';
}).catch(() => {});

document.querySelectorAll('.auth-tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    mode = tab.dataset.mode;
    document.querySelectorAll('.auth-tab').forEach((t) => t.classList.remove('active'));
    tab.classList.add('active');
    $('#submit-btn').textContent = mode === 'login' ? 'Sign in' : 'Create account';
    $('#pw-strength').hidden = mode === 'login';
    $('#password').setAttribute('autocomplete', mode === 'login' ? 'current-password' : 'new-password');
    $('#auth-msg').textContent = '';
    if (mode === 'register') checkStrength();
  });
});

// Show / hide password
$('#pw-toggle').addEventListener('click', () => {
  const p = $('#password');
  p.type = p.type === 'password' ? 'text' : 'password';
});

// Debounced password strength check during registration
let strengthTimer;
$('#password').addEventListener('input', () => {
  if (mode !== 'register') return;
  clearTimeout(strengthTimer);
  strengthTimer = setTimeout(checkStrength, 450);
});

async function checkStrength() {
  const password = $('#password').value;
  const username = $('#username').value;
  const fill = $('#pw-fill');
  const hints = $('#pw-hints');
  if (!password) { fill.style.width = '0%'; hints.innerHTML = ''; return; }
  try {
    const res = await fetch('/api/auth/check-password', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password, username }),
    });
    const data = await res.json();
    const errs = data.policyErrors || [];
    const breached = data.breach && data.breach.breached;
    let score = Math.max(0, 5 - errs.length);
    if (breached) score = 1;
    const pct = (score / 5) * 100;
    const colors = ['#b91c1c', '#b91c1c', '#c2770b', '#eab308', '#65a30d', '#16a34a'];
    fill.style.width = pct + '%';
    fill.style.background = colors[score];
    if (breached) {
      hints.innerHTML = `<span class="hint bad">⚠️ Found in ${Number(data.breach.count).toLocaleString('en')} known breaches — choose another</span>`;
    } else if (errs.length) {
      hints.innerHTML = errs.map((e) => `<span class="hint bad">• ${e}</span>`).join('');
    } else {
      hints.innerHTML = `<span class="hint good">✓ Strong password, not found in breaches</span>`;
    }
  } catch { /* ignore */ }
}

$('#auth-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = $('#username').value.trim();
  const password = $('#password').value;
  const msg = $('#auth-msg');
  const btn = $('#submit-btn');
  msg.className = 'auth-msg';
  msg.textContent = '';
  btn.disabled = true;
  btn.textContent = mode === 'login' ? 'Signing in...' : 'Creating...';
  try {
    const res = await fetch('/api/auth/' + mode, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed');
    location.href = '/';
  } catch (err) {
    msg.className = 'auth-msg error';
    msg.textContent = '✗ ' + err.message;
    btn.disabled = false;
    btn.textContent = mode === 'login' ? 'Sign in' : 'Create account';
  }
});
