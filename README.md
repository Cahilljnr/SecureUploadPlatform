# 🔐 SecureVault – Encrypted Upload Platform

A cloud-based platform where users can upload files and text data that is **AES-256-GCM encrypted before it ever leaves the browser**.

---

## Features

- **Client-side encryption** – data is encrypted in the browser using the Web Crypto API (AES-256-GCM + PBKDF2 key derivation)
- **Server-side double encryption** – the server adds a second AES-256-GCM layer before saving to disk
- **Any file type** – documents, images, videos, JSON, text, etc. (up to 100 MB)
- **Text/data upload** – paste raw text, credentials, notes, or JSON
- **Upload history** – view metadata of past uploads (contents stay encrypted)
- **Rate limiting** – max 30 uploads per 15 min per IP
- **Security headers** – Helmet.js sets CSP, HSTS, and other hardening headers

---

## How Encryption Works

```
User Passphrase
      │
      ▼
  PBKDF2 (100,000 iterations, SHA-256)  ← runs in browser
      │
      ▼
  AES-256-GCM Key  +  Random IV (12 bytes)
      │
      ▼
  Encrypted Blob  [salt | iv | ciphertext+authTag]
      │
      ▼  (sent to server)
  Server AES-256-GCM layer  +  Random IV
      │
      ▼
  Stored on disk as .enc file  ← two independent encryption layers
```

**Zero-knowledge**: the server never sees plaintext. The user's key is never transmitted.

---

## Run Locally

```bash
# 1. Install dependencies
npm install

# 2. Start the server
npm start

# 3. Open browser
# http://localhost:3000
```

---

## Deploy to the Cloud (Free)

### Option A – Render.com (recommended, free tier)

1. Push this folder to a GitHub repository
2. Go to [render.com](https://render.com) → New → Web Service
3. Connect your GitHub repo
4. Render reads `render.yaml` automatically
5. Click **Deploy** – you get a public URL like `https://secure-upload-platform.onrender.com`

### Option B – Railway.app

1. Push to GitHub
2. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
3. Set environment variable `SERVER_SECRET` to a 64-char random hex string
4. Deploy – get a public URL instantly

### Option C – Heroku

```bash
heroku create your-app-name
heroku config:set SERVER_SECRET=<64-char-hex>
git push heroku main
```

---

## Environment Variables

| Variable        | Description                                      | Default           |
|----------------|--------------------------------------------------|-------------------|
| `PORT`          | Port to listen on                                | `3000`            |
| `SERVER_SECRET` | Secret for server-side encryption key derivation | (change in prod!) |
| `NODE_ENV`      | `development` or `production`                    | `development`     |

---

## Project Structure

```
SecureUploadPlatform/
├── server.js              # Express backend
├── public/
│   ├── index.html         # Frontend UI
│   ├── style.css          # Styles
│   ├── crypto.js          # Client-side Web Crypto wrapper
│   └── app.js             # UI logic & API calls
├── uploads/               # Encrypted files stored here (auto-created)
├── package.json
├── render.yaml            # Render.com deployment config
├── Procfile               # Heroku/Railway config
└── .env                   # Local env vars (not committed)
```

---

## Security Notes

- Encryption keys are **never sent to the server** – only encrypted ciphertext is transmitted
- Each upload uses a **unique random IV** (initialization vector)
- Key derivation uses **PBKDF2 with 100,000 iterations** to resist brute-force attacks
- **Save your passphrase** – without it, uploaded data cannot be decrypted
- In production, consider replacing local file storage with AWS S3 or Google Cloud Storage
