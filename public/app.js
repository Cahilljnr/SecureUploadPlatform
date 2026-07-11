/**
 * app.js – Main UI logic for SecureVault (authenticated)
 */

// ── DOM refs ──────────────────────────────────────────────────────────────────
const encKeyInput  = document.getElementById('encKey');
const toggleKeyBtn = document.getElementById('toggleKeyVis');
const genKeyBtn    = document.getElementById('genKey');
const copyKeyBtn   = document.getElementById('copyKey');
const tabs         = document.querySelectorAll('.tab');
const tabContents  = document.querySelectorAll('.tab-content');
const dropZone     = document.getElementById('dropZone');
const fileInput    = document.getElementById('fileInput');
const fileList     = document.getElementById('fileList');
const textInput    = document.getElementById('textInput');
const uploadBtn    = document.getElementById('uploadBtn');
const progressArea = document.getElementById('progressArea');
const progressFill = document.getElementById('progressFill');
const progressText = document.getElementById('progressText');
const progressPct  = document.getElementById('progressPct');
const uploadResult = document.getElementById('uploadResult');
const historyList  = document.getElementById('historyList');
const statTotal    = document.getElementById('stat-total');
const statSize     = document.getElementById('stat-size');
const headerUser   = document.getElementById('headerUser');
const heroWelcome  = document.getElementById('heroWelcome');

let selectedFiles = [];
let activeTab     = 'file';
let currentUser   = null;

// ── Init: check auth ──────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', async () => {
  try {
    const res  = await fetch('/api/auth/me');
    const data = await res.json();

    if (!data.loggedIn) {
      window.location.replace('/login.html');
      return;
    }

    currentUser = data.user;
    renderUserNav(data.user);
    heroWelcome.innerHTML = `Welcome back, <strong>${escHtml(data.user.fullname)}</strong>! Your files are encrypted in your browser before upload.`;

    encKeyInput.value = ClientCrypto.generatePassphrase();
    loadHistory();
    loadStats();

  } catch {
    window.location.replace('/login.html');
  }
});

// ── User nav (top-right) ──────────────────────────────────────────────────────
function renderUserNav(user) {
  headerUser.innerHTML = `
    <div class="user-pill">
      <span class="user-avatar">${escHtml(user.fullname.charAt(0).toUpperCase())}</span>
      <span class="user-name">${escHtml(user.fullname)}</span>
      <button class="btn-logout" id="logoutBtn" title="Sign out">Sign out</button>
    </div>
  `;
  document.getElementById('logoutBtn').addEventListener('click', logout);
}

async function logout() {
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
  } finally {
    window.location.replace('/login.html');
  }
}

// ── Key controls ──────────────────────────────────────────────────────────────
toggleKeyBtn.addEventListener('click', () => {
  encKeyInput.type        = encKeyInput.type === 'password' ? 'text' : 'password';
  toggleKeyBtn.textContent = encKeyInput.type === 'password' ? '👁' : '🙈';
});
genKeyBtn.addEventListener('click', () => {
  encKeyInput.value = ClientCrypto.generatePassphrase();
  showToast('New key generated!');
});
copyKeyBtn.addEventListener('click', async () => {
  if (!encKeyInput.value) return;
  try {
    await navigator.clipboard.writeText(encKeyInput.value);
    showToast('Key copied to clipboard!');
  } catch {
    showToast('Copy failed – please copy manually.', true);
  }
});

// ── Tab switching ─────────────────────────────────────────────────────────────
tabs.forEach(tab => {
  tab.addEventListener('click', () => {
    tabs.forEach(t => t.classList.remove('active'));
    tabContents.forEach(c => c.classList.remove('active'));
    tab.classList.add('active');
    activeTab = tab.dataset.tab;
    document.getElementById(`tab-${activeTab}`).classList.add('active');
    clearResult();
  });
});

// ── Drag & Drop ───────────────────────────────────────────────────────────────
dropZone.addEventListener('dragover',  e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  handleFiles([...e.dataTransfer.files]);
});
dropZone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change',   () => handleFiles([...fileInput.files]));

function handleFiles(files) {
  selectedFiles = [...selectedFiles, ...files];
  renderFileList();
  clearResult();
}

function renderFileList() {
  fileList.innerHTML = '';
  selectedFiles.forEach((file, idx) => {
    const item = document.createElement('div');
    item.className = 'file-item';
    item.innerHTML = `
      <span class="fi-icon">${getFileIcon(file.type)}</span>
      <span class="fi-name" title="${escHtml(file.name)}">${escHtml(file.name)}</span>
      <span class="fi-size">${formatBytes(file.size)}</span>
      <button class="fi-remove" data-idx="${idx}" title="Remove">✕</button>
    `;
    fileList.appendChild(item);
  });
  fileList.querySelectorAll('.fi-remove').forEach(btn => {
    btn.addEventListener('click', () => {
      selectedFiles.splice(Number(btn.dataset.idx), 1);
      renderFileList();
    });
  });
}

// ── Upload ────────────────────────────────────────────────────────────────────
uploadBtn.addEventListener('click', startUpload);

async function startUpload() {
  const passphrase = encKeyInput.value.trim();
  if (!passphrase) { showResult('error', 'Please enter or generate an encryption key first.'); return; }

  if (activeTab === 'file') {
    if (selectedFiles.length === 0) { showResult('error', 'Please select at least one file.'); return; }
    await uploadFiles(passphrase);
  } else {
    const text = textInput.value.trim();
    if (!text) { showResult('error', 'Please enter some text or data.'); return; }
    await uploadText(text, passphrase);
  }
}

async function uploadFiles(passphrase) {
  setUIBusy(true);
  const results = [];

  for (let i = 0; i < selectedFiles.length; i++) {
    const file = selectedFiles[i];
    setProgress(`Encrypting "${file.name}"…`, Math.round((i / selectedFiles.length) * 40));

    try {
      const buffer    = await file.arrayBuffer();
      const encrypted = await ClientCrypto.encrypt(buffer, passphrase);

      setProgress(`Uploading "${file.name}"…`, 40 + Math.round((i / selectedFiles.length) * 55));

      const formData = new FormData();
      formData.append('file', new Blob([encrypted], { type: 'application/octet-stream' }), file.name + '.enc');

      const res  = await fetch('/api/upload', { method: 'POST', body: formData });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error || 'Upload failed');
      results.push({ name: file.name, id: json.id, ok: true });

    } catch (err) {
      results.push({ name: file.name, ok: false, error: err.message });
    }
  }

  setProgress('Done!', 100);
  const ok  = results.filter(r => r.ok);
  const bad = results.filter(r => !r.ok);

  let html = `<strong>✅ ${ok.length} file(s) encrypted &amp; uploaded</strong>`;
  if (ok.length)  html += '<ul style="margin:.5rem 0 0 1rem">' + ok.map(r  => `<li>${escHtml(r.name)} <code style="font-size:.75rem;opacity:.7">[${r.id.slice(0,8)}…]</code></li>`).join('') + '</ul>';
  if (bad.length) html += `<br><strong style="color:#fca5a5">❌ ${bad.length} failed:</strong><ul style="margin:.3rem 0 0 1rem">` + bad.map(r => `<li>${escHtml(r.name)}: ${escHtml(r.error)}</li>`).join('') + '</ul>';
  html += `<br><span style="font-size:.82rem;opacity:.7">🔑 Keep your key: <code>${encKeyInput.value}</code></span>`;

  showResult('success', html);
  selectedFiles = [];
  renderFileList();
  setUIBusy(false);
  loadHistory();
  loadStats();
}

async function uploadText(text, passphrase) {
  setUIBusy(true);
  setProgress('Encrypting text…', 30);
  try {
    const encrypted = await ClientCrypto.encrypt(new TextEncoder().encode(text), passphrase);
    const b64       = ClientCrypto.toBase64(encrypted);

    setProgress('Uploading encrypted data…', 70);
    const res  = await fetch('/api/upload', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ textPayload: b64 })
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || 'Upload failed');

    setProgress('Done!', 100);
    showResult('success',
      `<strong>✅ Text encrypted &amp; uploaded</strong><br>
       ID: <code>${json.id}</code> &nbsp;·&nbsp; ${new Date(json.uploadedAt).toLocaleString()}<br>
       <span style="font-size:.82rem;opacity:.7">🔑 Key: <code>${encKeyInput.value}</code></span>`
    );
    textInput.value = '';
  } catch (err) {
    showResult('error', `<strong>Upload failed</strong><br>${escHtml(err.message)}`);
  }
  setUIBusy(false);
  loadHistory();
  loadStats();
}

// ── History ───────────────────────────────────────────────────────────────────
async function loadHistory() {
  try {
    const res  = await fetch('/api/uploads');
    if (res.status === 401) { window.location.replace('/login.html'); return; }
    const data = await res.json();

    if (!data.length) {
      historyList.innerHTML = '<div class="empty-state">📭 No uploads yet. Upload something above.</div>';
      return;
    }
    historyList.innerHTML = data.map(item => `
      <div class="history-item">
        <span class="hi-icon">${getFileIcon(item.mimeType)}</span>
        <div class="hi-info">
          <div class="hi-name">${escHtml(item.originalName)}</div>
          <div class="hi-meta">
            ${formatBytes(item.size)} &nbsp;·&nbsp;
            ${new Date(item.uploadedAt).toLocaleString()} &nbsp;·&nbsp;
            <code style="font-size:.75rem">${item.id.slice(0,8)}…</code>
          </div>
        </div>
        <span class="hi-badge">🔐 ${item.layers}-layer AES-256</span>
      </div>
    `).join('');
  } catch {
    historyList.innerHTML = '<div class="empty-state">Could not load history.</div>';
  }
}

async function loadStats() {
  try {
    const res  = await fetch('/api/stats');
    const data = await res.json();
    statTotal.textContent = data.totalUploads;
    statSize.textContent  = data.totalSizeMB;
  } catch { /* silent */ }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function setProgress(text, pct) {
  progressArea.classList.remove('hidden');
  progressText.textContent = text;
  progressPct.textContent  = pct + '%';
  progressFill.style.width = pct + '%';
}
function setUIBusy(busy) {
  uploadBtn.disabled = busy;
  if (busy)  { progressArea.classList.remove('hidden'); uploadResult.classList.add('hidden'); }
  else       { setTimeout(() => progressArea.classList.add('hidden'), 1500); }
}
function showResult(type, html) {
  uploadResult.className = `result-box ${type}`;
  uploadResult.innerHTML = html;
  uploadResult.classList.remove('hidden');
  uploadResult.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
function clearResult() { uploadResult.classList.add('hidden'); }
function formatBytes(b) {
  if (!b) return '0 B';
  const k = 1024, s = ['B','KB','MB','GB'], i = Math.floor(Math.log(b)/Math.log(k));
  return (b/Math.pow(k,i)).toFixed(1)+' '+s[i];
}
function getFileIcon(m) {
  m = (m||'').toLowerCase();
  if (m.includes('image'))  return '🖼️';
  if (m.includes('pdf'))    return '📄';
  if (m.includes('video'))  return '🎬';
  if (m.includes('audio'))  return '🎵';
  if (m.includes('zip')||m.includes('compress')) return '🗜️';
  if (m.includes('text')||m.includes('json'))    return '📝';
  if (m.includes('sheet')||m.includes('excel'))  return '📊';
  if (m.includes('word')||m.includes('document'))return '📃';
  return '📁';
}
function escHtml(s='') {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function showToast(msg, isError=false) {
  const t = document.createElement('div');
  t.textContent = msg;
  Object.assign(t.style, {
    position:'fixed', bottom:'1.5rem', right:'1.5rem', zIndex:'9999',
    background: isError ? '#ef4444' : '#10b981',
    color:'#fff', padding:'.75rem 1.2rem', borderRadius:'8px',
    fontSize:'.88rem', fontWeight:'500', boxShadow:'0 4px 14px rgba(0,0,0,.4)',
    transition:'opacity .4s'
  });
  document.body.appendChild(t);
  setTimeout(()=>{ t.style.opacity='0'; setTimeout(()=>t.remove(),400); }, 2500);
}
