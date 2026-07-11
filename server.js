require('dotenv').config();
const express      = require('express');
const multer       = require('multer');
const path         = require('path');
const fs           = require('fs');
const crypto       = require('crypto');
const { v4: uuidv4 } = require('uuid');
const cors         = require('cors');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const bcrypt       = require('bcryptjs');
const session      = require('express-session');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Data directories ──────────────────────────────────────────────────────────
const DATA_DIR     = path.join(__dirname, 'data');
const UPLOADS_DIR  = path.join(__dirname, 'uploads');
const USERS_FILE   = path.join(DATA_DIR, 'users.json');

[DATA_DIR, UPLOADS_DIR].forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify([]));

// ── Helpers: users store ──────────────────────────────────────────────────────
function readUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
  catch { return []; }
}
function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}
function findUser(username) {
  return readUsers().find(u => u.username.toLowerCase() === username.toLowerCase());
}

// ── Helpers: per-user manifest ────────────────────────────────────────────────
function manifestPath(userId) {
  return path.join(DATA_DIR, `manifest_${userId}.json`);
}
function readManifest(userId) {
  const f = manifestPath(userId);
  try { return JSON.parse(fs.readFileSync(f, 'utf8')); }
  catch { return []; }
}
function writeManifest(userId, data) {
  fs.writeFileSync(manifestPath(userId), JSON.stringify(data, null, 2));
}

// ── Server-side envelope encryption ──────────────────────────────────────────
function serverEncrypt(buffer) {
  const key    = crypto.scryptSync(process.env.SERVER_SECRET || 'change-me-in-production', 'sv1', 32);
  const iv     = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc    = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const tag    = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]);
}

// ── Security middleware ───────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'"],
      styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:    ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'"],
      imgSrc:     ["'self'", "data:"],
    }
  }
}));
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ── Session ───────────────────────────────────────────────────────────────────
app.use(session({
  secret:            process.env.SESSION_SECRET || 'securevault-session-secret-change-me',
  resave:            false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure:   process.env.NODE_ENV === 'production',
    maxAge:   7 * 24 * 60 * 60 * 1000  // 7 days
  }
}));

// ── Static files ──────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ── Auth middleware ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.status(401).json({ error: 'Not authenticated. Please log in.' });
}

// ── Rate limiters ─────────────────────────────────────────────────────────────
const authLimiter   = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many attempts. Try again later.' } });
const uploadLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, message: { error: 'Too many uploads. Try again later.' } });

// ═══════════════════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// POST /api/auth/register
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { username, password, fullname } = req.body;

    if (!username || !password || !fullname)
      return res.status(400).json({ error: 'All fields are required.' });

    if (username.length < 3 || username.length > 30)
      return res.status(400).json({ error: 'Username must be 3–30 characters.' });

    if (!/^[a-zA-Z0-9_]+$/.test(username))
      return res.status(400).json({ error: 'Username can only contain letters, numbers, and underscores.' });

    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters.' });

    if (findUser(username))
      return res.status(409).json({ error: 'Username already taken.' });

    const hashed  = await bcrypt.hash(password, 12);
    const userId  = uuidv4();
    const users   = readUsers();

    users.push({
      id:         userId,
      username:   username.trim(),
      fullname:   fullname.trim(),
      password:   hashed,
      createdAt:  new Date().toISOString()
    });
    writeUsers(users);

    // Auto-login after register
    req.session.userId   = userId;
    req.session.username = username.trim();
    req.session.fullname = fullname.trim();

    res.status(201).json({
      success:  true,
      message:  'Account created successfully.',
      user:     { username: username.trim(), fullname: fullname.trim() }
    });

  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed.' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Username and password are required.' });

    const user = findUser(username);
    if (!user) return res.status(401).json({ error: 'Invalid username or password.' });

    const match = await bcrypt.compare(password, user.password);
    if (!match)  return res.status(401).json({ error: 'Invalid username or password.' });

    req.session.userId   = user.id;
    req.session.username = user.username;
    req.session.fullname = user.fullname;

    res.json({
      success: true,
      user:    { username: user.username, fullname: user.fullname }
    });

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed.' });
  }
});

// POST /api/auth/logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// GET /api/auth/me – check current session
app.get('/api/auth/me', (req, res) => {
  if (req.session && req.session.userId) {
    return res.json({
      loggedIn: true,
      user: { username: req.session.username, fullname: req.session.fullname }
    });
  }
  res.json({ loggedIn: false });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  UPLOAD ROUTES  (protected)
// ═══════════════════════════════════════════════════════════════════════════════
const storage = multer.memoryStorage();
const upload  = multer({ storage, limits: { fileSize: 100 * 1024 * 1024 } });

// POST /api/upload
app.post('/api/upload', requireAuth, uploadLimiter, upload.single('file'), (req, res) => {
  try {
    if (!req.file && !req.body.textPayload)
      return res.status(400).json({ error: 'No data received.' });

    const id        = uuidv4();
    const timestamp = new Date().toISOString();
    let rawBuffer, originalName, mimeType;

    if (req.file) {
      rawBuffer    = req.file.buffer;
      originalName = req.file.originalname;
      mimeType     = req.file.mimetype;
    } else {
      rawBuffer    = Buffer.from(req.body.textPayload, 'base64');
      originalName = 'text-payload.enc';
      mimeType     = 'application/octet-stream';
    }

    const doubleEncrypted = serverEncrypt(rawBuffer);
    const filename        = `${id}.enc`;
    fs.writeFileSync(path.join(UPLOADS_DIR, filename), doubleEncrypted);

    const manifest = readManifest(req.session.userId);
    manifest.unshift({ id, filename, originalName, mimeType, size: rawBuffer.length, uploadedAt: timestamp, encrypted: true, layers: 2 });
    writeManifest(req.session.userId, manifest);

    res.status(200).json({ success: true, id, message: 'Encrypted and stored.', uploadedAt: timestamp });

  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Upload failed.' });
  }
});

// GET /api/uploads – current user's uploads only
app.get('/api/uploads', requireAuth, (req, res) => {
  const manifest = readManifest(req.session.userId);
  res.json(manifest.map(({ id, originalName, mimeType, size, uploadedAt, encrypted, layers }) =>
    ({ id, originalName, mimeType, size, uploadedAt, encrypted, layers })
  ));
});

// GET /api/stats
app.get('/api/stats', requireAuth, (req, res) => {
  const manifest  = readManifest(req.session.userId);
  const totalSize = manifest.reduce((s, i) => s + (i.size || 0), 0);
  res.json({ totalUploads: manifest.length, totalSizeMB: (totalSize / (1024 * 1024)).toFixed(2) });
});

// ── Fallback – serve frontend ──────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🔐 SecureVault running at http://localhost:${PORT}\n`);
});
