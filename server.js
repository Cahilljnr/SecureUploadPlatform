require('dotenv').config();
const express    = require('express');
const multer     = require('multer');
const path       = require('path');
const fs         = require('fs');
const crypto     = require('crypto');
const { v4: uuidv4 } = require('uuid');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const bcrypt     = require('bcryptjs');
const session    = require('express-session');
const RedisStore = require('connect-redis').default;
const Redis      = require('ioredis');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Redis client ──────────────────────────────────────────────────────────────
const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
const redisClient = new Redis(redisUrl, {
  tls: redisUrl.startsWith('rediss://') ? { rejectUnauthorized: false } : undefined,
  maxRetriesPerRequest: null
});
redisClient.on('error',   err => console.error('Redis error:', err));
redisClient.on('connect', ()  => console.log('✅ Redis connected'));

// ── Uploads dir (local dev only; ephemeral on Render) ────────────────────────
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ── Helpers: users in Redis ───────────────────────────────────────────────────
async function findUser(username) {
  const data = await redisClient.get(`user:${username.toLowerCase()}`);
  return data ? JSON.parse(data) : null;
}
async function saveUser(user) {
  const str = JSON.stringify(user);
  await redisClient.set(`user:${user.username.toLowerCase()}`, str);
  await redisClient.set(`userid:${user.id}`, str);
}

// ── Helpers: per-user manifest in Redis ──────────────────────────────────────
async function readManifest(userId) {
  const data = await redisClient.get(`manifest:${userId}`);
  return data ? JSON.parse(data) : [];
}
async function writeManifest(userId, data) {
  await redisClient.set(`manifest:${userId}`, JSON.stringify(data));
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
// Required on Render (sits behind a proxy) for rate limiter and secure cookies
app.set('trust proxy', 1);

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
  store: new RedisStore({ client: redisClient }),
  secret:            process.env.SESSION_SECRET || 'securevault-dev-secret',
  resave:            false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure:   process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
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
    if (await findUser(username))
      return res.status(409).json({ error: 'Username already taken.' });

    const hashed = await bcrypt.hash(password, 12);
    const userId = uuidv4();
    await saveUser({ id: userId, username: username.trim(), fullname: fullname.trim(), password: hashed, createdAt: new Date().toISOString() });

    req.session.userId   = userId;
    req.session.username = username.trim();
    req.session.fullname = fullname.trim();

    req.session.save(err => {
      if (err) { console.error('Session save error:', err); return res.status(500).json({ error: 'Registration failed.' }); }
      res.status(201).json({ success: true, message: 'Account created successfully.', user: { username: username.trim(), fullname: fullname.trim() } });
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

    const user = await findUser(username);
    if (!user) return res.status(401).json({ error: 'Invalid username or password.' });

    const match = await bcrypt.compare(password, user.password);
    if (!match)  return res.status(401).json({ error: 'Invalid username or password.' });

    req.session.userId   = user.id;
    req.session.username = user.username;
    req.session.fullname = user.fullname;

    req.session.save(err => {
      if (err) { console.error('Session save error:', err); return res.status(500).json({ error: 'Login failed.' }); }
      res.json({ success: true, user: { username: user.username, fullname: user.fullname } });
    });

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed.' });
  }
});

// POST /api/auth/logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// GET /api/auth/me
app.get('/api/auth/me', (req, res) => {
  if (req.session && req.session.userId) {
    return res.json({ loggedIn: true, user: { username: req.session.username, fullname: req.session.fullname } });
  }
  res.json({ loggedIn: false });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  UPLOAD ROUTES  (protected)
// ═══════════════════════════════════════════════════════════════════════════════
const storage = multer.memoryStorage();
const upload  = multer({ storage, limits: { fileSize: 100 * 1024 * 1024 } });

// POST /api/upload
app.post('/api/upload', requireAuth, uploadLimiter, upload.single('file'), async (req, res) => {
  try {
    if (!req.file && !req.body.textPayload)
      return res.status(400).json({ error: 'No data received.' });

    const id = uuidv4();
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
    // Store encrypted file in Redis (base64 encoded)
    await redisClient.set(`file:${id}`, doubleEncrypted.toString('base64'));

    // Save share record so anyone with the link can access it
    await redisClient.set(`share:${id}`, JSON.stringify({
      id, originalName, mimeType,
      size:       rawBuffer.length,
      uploadedAt: timestamp,
      uploadedBy: req.session.username,
      layers:     2
    }));

    const manifest = await readManifest(req.session.userId);
    manifest.unshift({ id, originalName, mimeType, size: rawBuffer.length, uploadedAt: timestamp, encrypted: true, layers: 2 });
    await writeManifest(req.session.userId, manifest);

    res.status(200).json({ success: true, id, shareUrl: `/share/${id}`, message: 'Encrypted and stored.', uploadedAt: timestamp });

  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Upload failed.' });
  }
});

// GET /api/uploads
app.get('/api/uploads', requireAuth, async (req, res) => {
  const manifest = await readManifest(req.session.userId);
  res.json(manifest.map(({ id, originalName, mimeType, size, uploadedAt, encrypted, layers }) =>
    ({ id, originalName, mimeType, size, uploadedAt, encrypted, layers })
  ));
});

// GET /api/stats
app.get('/api/stats', requireAuth, async (req, res) => {
  const manifest  = await readManifest(req.session.userId);
  const totalSize = manifest.reduce((s, i) => s + (i.size || 0), 0);
  res.json({ totalUploads: manifest.length, totalSizeMB: (totalSize / (1024 * 1024)).toFixed(2) });
});

// GET /api/share/:id – public metadata for shared file (no auth required)
app.get('/api/share/:id', async (req, res) => {
  try {
    const { id } = req.params;
    // Look up share record
    const shareData = await redisClient.get(`share:${id}`);
    if (!shareData) return res.status(404).json({ error: 'File not found or link has expired.' });
    const share = JSON.parse(shareData);
    // Return only metadata, never the encrypted bytes
    res.json({
      id:           share.id,
      originalName: share.originalName,
      mimeType:     share.mimeType,
      size:         share.size,
      uploadedAt:   share.uploadedAt,
      uploadedBy:   share.uploadedBy,
      layers:       share.layers
    });
  } catch (err) {
    console.error('Share lookup error:', err);
    res.status(500).json({ error: 'Could not retrieve file info.' });
  }
});

// POST /api/share/:id/decrypt – submit key, get decrypted file (public)
app.post('/api/share/:id/decrypt', async (req, res) => {
  try {
    const { id } = req.params;
    const shareData = await redisClient.get(`share:${id}`);
    if (!shareData) return res.status(404).json({ error: 'File not found.' });
    const share = JSON.parse(shareData);

    // Fetch the doubly-encrypted blob from Redis
    const encB64 = await redisClient.get(`file:${id}`);
    if (!encB64) return res.status(404).json({ error: 'File data not found.' });

    // Strip server-side encryption layer: layout is iv(12) | tag(16) | ciphertext
    const encBuffer = Buffer.from(encB64, 'base64');
    const key      = crypto.scryptSync(process.env.SERVER_SECRET || 'change-me-in-production', 'sv1', 32);
    const iv       = encBuffer.slice(0, 12);
    const tag      = encBuffer.slice(12, 28);
    const ciphered = encBuffer.slice(28);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);

    let clientEncrypted;
    try {
      clientEncrypted = Buffer.concat([decipher.update(ciphered), decipher.final()]);
    } catch (e) {
      console.error('Server-layer decrypt failed:', e.message);
      return res.status(500).json({ error: 'Server decryption failed. The SERVER_SECRET may have changed.' });
    }

    // Strip .enc suffix from original name for download
    const cleanName = share.originalName.replace(/\.enc$/i, '');

    // Return the client-encrypted blob — the browser decrypts with the user's key
    res.json({
      clientEncrypted: clientEncrypted.toString('base64'),
      originalName:    cleanName,
      mimeType:        share.mimeType
    });
  } catch (err) {
    console.error('Share decrypt error:', err);
    res.status(500).json({ error: 'Could not retrieve file.' });
  }
});

// ── Fallback – serve frontend ─────────────────────────────────────────────────
// Root always goes to login first; authenticated users are redirected by app.js
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Shared file view – public, no auth required
app.get('/share/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'share.html'));
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🔐 SecureVault running at http://localhost:${PORT}\n`);
});
