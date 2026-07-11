/**
 * crypto.js – Client-side AES-256-GCM encryption using the Web Crypto API
 *
 * Flow:
 *   1. Derive a 256-bit AES key from the user's passphrase via PBKDF2
 *   2. Generate a random 12-byte IV per encryption operation
 *   3. Encrypt the data with AES-256-GCM
 *   4. Return a Uint8Array: [ salt(16) | iv(12) | ciphertext+authTag ]
 */

const ClientCrypto = (() => {

  const PBKDF2_ITERATIONS = 100_000;
  const SALT_LENGTH       = 16;   // bytes
  const IV_LENGTH         = 12;   // bytes – recommended for GCM

  /**
   * Derive a CryptoKey from a passphrase string.
   * @param {string}     passphrase
   * @param {Uint8Array} salt
   * @returns {Promise<CryptoKey>}
   */
  async function deriveKey(passphrase, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      enc.encode(passphrase),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name:       'PBKDF2',
        salt:       salt,
        iterations: PBKDF2_ITERATIONS,
        hash:       'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypt arbitrary data (ArrayBuffer or Uint8Array) with AES-256-GCM.
   * Returns a Uint8Array: salt(16) | iv(12) | ciphertext(+16-byte GCM auth tag)
   *
   * @param {ArrayBuffer|Uint8Array} data
   * @param {string} passphrase
   * @returns {Promise<Uint8Array>}
   */
  async function encrypt(data, passphrase) {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    const iv   = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const key  = await deriveKey(passphrase, salt);

    const cipherBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      data instanceof Uint8Array ? data : new Uint8Array(data)
    );

    // Pack: salt | iv | ciphertext
    const result = new Uint8Array(SALT_LENGTH + IV_LENGTH + cipherBuffer.byteLength);
    result.set(salt, 0);
    result.set(iv,   SALT_LENGTH);
    result.set(new Uint8Array(cipherBuffer), SALT_LENGTH + IV_LENGTH);
    return result;
  }

  /**
   * Generate a cryptographically random passphrase (Base64url, 32 bytes → 43 chars).
   * @returns {string}
   */
  function generatePassphrase() {
    const bytes  = crypto.getRandomValues(new Uint8Array(32));
    const b64    = btoa(String.fromCharCode(...bytes));
    // Make URL-safe
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  /**
   * Decrypt data encrypted by the encrypt() function above.
   * @param {Uint8Array} data  – salt(16) | iv(12) | ciphertext
   * @param {string}     passphrase
   * @returns {Promise<Uint8Array>}
   */
  async function decrypt(data, passphrase) {
    const salt       = data.slice(0, SALT_LENGTH);
    const iv         = data.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    const ciphertext = data.slice(SALT_LENGTH + IV_LENGTH);
    const key        = await deriveKey(passphrase, salt);
    const plainBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext
    );
    return new Uint8Array(plainBuffer);
  }

  /**
   * Convert a Base64 string back to a Uint8Array.
   */
  function fromBase64(b64) {
    const binary = atob(b64);
    const bytes  = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  /**
   * Convert a Uint8Array to a Base64 string (for transport as form field).
   */
  function toBase64(uint8Array) {
    let binary = '';
    for (let i = 0; i < uint8Array.length; i++) {
      binary += String.fromCharCode(uint8Array[i]);
    }
    return btoa(binary);
  }

  return { encrypt, decrypt, generatePassphrase, toBase64, fromBase64 };
})();
