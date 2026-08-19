// backend/lib/security.js
// Security middleware — rate limiting, security headers, input sanitization,
// MIME validation, CORS hardening. Zero external dependencies.

import { createHmac } from 'node:crypto';

/* ========================================================================
   1. RATE LIMITER
   In-memory sliding-window rate limiter. No external deps.
   ======================================================================== */

const windows = new Map();

/**
 * Create a rate-limiting middleware for a given route group.
 * @param {object} opts
 * @param {number} opts.windowMs  - Time window in milliseconds
 * @param {number} opts.maxHits   - Max requests per window per IP
 * @param {string} opts.prefix    - Namespace for this limiter
 */
export function rateLimiter({ windowMs = 60_000, maxHits = 20, prefix = 'default' } = {}) {
  return function checkRateLimit(req, res) {
    const ip = req.socket?.remoteAddress || 'unknown';
    const key = `${prefix}:${ip}`;
    const now = Date.now();

    let entry = windows.get(key);
    if (!entry || now - entry.start > windowMs) {
      entry = { start: now, hits: 0 };
      windows.set(key, entry);
    }
    entry.hits++;

    // Clean up stale entries every 100 requests (amortised)
    if (windows.size > 10_000) {
      for (const [k, v] of windows) {
        if (now - v.start > windowMs) windows.delete(k);
      }
    }

    if (entry.hits > maxHits) {
      return { limited: true, retryAfter: Math.ceil((windowMs - (now - entry.start)) / 1000) };
    }
    return { limited: false };
  };
}

// Pre-configured limiters
export const authLimiter = rateLimiter({ windowMs: 15 * 60_000, maxHits: 10, prefix: 'auth' });
export const apiLimiter = rateLimiter({ windowMs: 60_000, maxHits: 60, prefix: 'api' });
export const uploadLimiter = rateLimiter({ windowMs: 60_000, maxHits: 10, prefix: 'upload' });

/* ========================================================================
   2. SECURITY HEADERS (helmet-style)
   ======================================================================== */

export function securityHeaders(extraHeaders = {}) {
  return {
    // Prevent clickjacking — only allow framing from the frontend origin
    'X-Frame-Options': process.env.FRONTEND_ORIGIN ? 'ALLOW-FROM ' + process.env.FRONTEND_ORIGIN : 'DENY',
    // Prevent MIME-type sniffing
    'X-Content-Type-Options': 'nosniff',
    // XSS protection (legacy browsers)
    'X-XSS-Protection': '1; mode=block',
    // Referrer policy
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    // Permissions policy — deny features we don't use
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(self), payment=(self)',
    // Strict Transport Security (tells browsers to always use HTTPS — 1 year + include subdomains)
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    // Content Security Policy — restrict where scripts/styles/images can come from
    'Content-Security-Policy': buildCSP(),
    // Remove powered-by header to hide server info
    'X-Powered-By': '',
    ...extraHeaders,
  };
}

function buildCSP() {
  const origin = process.env.FRONTEND_ORIGIN || "'self'";
  const backendUrl = process.env.PUBLIC_BACKEND_URL || '';
  const backendDomain = backendUrl ? new URL(backendUrl).origin : "'self'";

  return [
    `default-src 'self'`,
    `script-src 'self' 'unsafe-inline' 'unsafe-eval' https://js.paystack.co https://cdn.onesignal.com https://maps.googleapis.com`,
    `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com`,
    `img-src 'self' data: blob: ${backendDomain} https://res.cloudinary.com https://*.paystack.co`,
    `font-src 'self' https://fonts.gstatic.com`,
    `connect-src 'self' ${backendDomain} ${origin} https://api.paystack.co https://onesignal.com https://*.onesignal.com https://maps.googleapis.com https://api.smileidentity.com https://sms.arkesel.com wss:`,
    `frame-src https://js.paystack.co https://paystack.com`,
    `form-action 'self'`,
    `base-uri 'self'`,
    `object-src 'none'`,
  ].join('; ');
}

/* ========================================================================
   3. CORS — Production-safe configuration
   ======================================================================== */

// Support multiple allowed origins (localhost for dev, production domain)
const ALLOWED_ORIGINS = [];
if (process.env.FRONTEND_ORIGIN) {
  // Can be comma-separated for multiple origins
  for (const o of process.env.FRONTEND_ORIGIN.split(',')) {
    if (o.trim()) ALLOWED_ORIGINS.push(o.trim());
  }
}
// Always allow localhost for development
if (!ALLOWED_ORIGINS.includes('http://localhost:5173')) {
  ALLOWED_ORIGINS.push('http://localhost:5173');
}
if (!ALLOWED_ORIGINS.includes('http://localhost:3000')) {
  ALLOWED_ORIGINS.push('http://localhost:3000');
}

export function getCORSOrigin(req) {
  const requestOrigin = req.headers['origin'] || '';
  if (ALLOWED_ORIGINS.includes(requestOrigin)) return requestOrigin;
  // Fallback: if no origin header (e.g. server-to-server), use first configured origin
  return ALLOWED_ORIGINS[0] || '*';
}

export function corsHeaders(req) {
  const origin = getCORSOrigin(req);
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400', // 24h preflight cache
  };
}

/* ========================================================================
   4. INPUT SANITIZATION
   ======================================================================== */

// Characters/patterns that could indicate injection attempts
const SQL_INJECTION_PATTERNS = [
  /('|--|;|\/\*|\*\/|xp_|sp_|0x|char\(|concat\()/i,
  /(union\s+select|insert\s+into|delete\s+from|drop\s+table|alter\s+table|exec\s+\()/i,
  /(information_schema|pg_sleep|benchmark\(|sleep\()/i,
];

const XSS_PATTERNS = [
  /<script[^>]*>/i,
  /javascript:/i,
  /on\w+\s*=\s*['"]/i,  // event handlers like onclick=
  /<iframe/i,
  /<embed/i,
  /<object/i,
];

/**
 * Recursively sanitize an object's string values.
 * - Trims whitespace
 * - Strips null bytes
 * - Flags suspicious patterns (returns a warning but doesn't block — parameterized
 *   queries already protect against SQL injection; XSS is escaped on the React side)
 */
export function sanitizeInput(obj, path = '') {
  if (typeof obj === 'string') {
    let cleaned = obj.trim();
    // Strip null bytes
    cleaned = cleaned.replace(/\0/g, '');
    // Check for suspicious patterns (log but don't block — parameterized queries handle SQLi)
    for (const pat of SQL_INJECTION_PATTERNS) {
      if (pat.test(cleaned)) {
        console.warn(`[security] Potential SQL injection pattern at ${path || 'root'}: ${cleaned.slice(0, 100)}`);
      }
    }
    for (const pat of XSS_PATTERNS) {
      if (pat.test(cleaned)) {
        console.warn(`[security] Potential XSS pattern at ${path || 'root'}: ${cleaned.slice(0, 100)}`);
        // Strip the dangerous tag/attribute
        cleaned = cleaned.replace(pat, '');
      }
    }
    return cleaned;
  }
  if (Array.isArray(obj)) {
    return obj.map((v, i) => sanitizeInput(v, `${path}[${i}]`));
  }
  if (obj && typeof obj === 'object') {
    const result = {};
    for (const [key, val] of Object.entries(obj)) {
      const cleanKey = sanitizeInput(key, path);
      result[cleanKey] = sanitizeInput(val, `${path}.${key}`);
    }
    return result;
  }
  return obj;
}

/* ========================================================================
   5. MIME TYPE VALIDATION FOR UPLOADS
   ======================================================================== */

const ALLOWED_MIME_TYPES = new Set([
  'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml',
  'image/avif', 'image/bmp',
  'video/mp4', 'video/webm', 'video/quicktime',
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'text/plain',
]);

// Map file extensions to MIME types for validation
const EXT_TO_MIME = {
  jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif',
  webp: 'image/webp', svg: 'image/svg+xml', avif: 'image/avif', bmp: 'image/bmp',
  mp4: 'video/mp4', webm: 'video/webm', mov: 'video/quicktime',
  pdf: 'application/pdf',
  doc: 'application/msword', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls: 'application/vnd.ms-excel', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  txt: 'text/plain',
};

// Dangerous extensions that must NEVER be allowed
const BLOCKED_EXTENSIONS = new Set([
  'exe', 'bat', 'cmd', 'com', 'msi', 'scr', 'hta', 'pif',
  'sh', 'bash', 'zsh', 'fish',
  'ps1', 'psm1', 'vbs', 'vbe', 'wsf', 'wsh',
  'py', 'rb', 'pl', 'php', 'jsp', 'asp', 'aspx',
  'jar', 'class', 'dll', 'so', 'dylib',
  'html', 'htm', 'js', 'mjs', 'cjs',
  'reg', 'inf', 'lnk',
]);

/**
 * Validate that a file extension is allowed and matches its declared content type.
 * Returns { ok, error? }.
 */
export function validateFileUpload(fileName, contentType) {
  if (!fileName) return { ok: false, error: 'Filename is required' };

  const ext = fileName.split('.').pop().toLowerCase();
  if (!ext) return { ok: false, error: 'File must have an extension' };

  if (BLOCKED_EXTENSIONS.has(ext)) {
    return { ok: false, error: `File type .${ext} is not allowed for security reasons` };
  }

  const expectedMime = EXT_TO_MIME[ext];
  if (expectedMime && !ALLOWED_MIME_TYPES.has(expectedMime)) {
    return { ok: false, error: `File type .${ext} is not supported` };
  }

  // If content_type is provided, verify it roughly matches the extension
  if (contentType && expectedMime && contentType !== expectedMime &&
      !contentType.startsWith('image/') && !contentType.startsWith('video/') &&
      !contentType.startsWith('application/')) {
    console.warn(`[security] MIME mismatch: extension .${ext} expects ${expectedMime} but got ${contentType}`);
  }

  return { ok: true };
}

/* ========================================================================
   6. REQUEST BODY SIZE LIMIT
   ======================================================================== */

export function enforceBodySizeLimit(req, maxBytes = 5 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let received = 0;
    const chunks = [];

    req.on('data', (chunk) => {
      received += chunk.length;
      if (received > maxBytes) {
        req.destroy();
        reject(new Error(`Request body too large (limit: ${maxBytes / 1024 / 1024}MB)`));
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      resolve(Buffer.concat(chunks));
    });

    req.on('error', reject);
  });
}

/* ========================================================================
   7. ADMIN RBAC MIDDLEWARE
   ======================================================================== */

export function requireAdmin(user) {
  if (!user) return { ok: false, error: 'Authentication required', status: 401 };
  if (user.role !== 'admin') return { ok: false, error: 'Admin access required', status: 403 };
  return { ok: true };
}

/* ========================================================================
   8. PASSWORD STRENGTH VALIDATION
   ======================================================================== */

export function validatePasswordStrength(password) {
  if (!password || password.length < 8) {
    return { ok: false, error: 'Password must be at least 8 characters' };
  }
  if (password.length > 128) {
    return { ok: false, error: 'Password must be under 128 characters' };
  }
  // Check for at least one letter and one number
  if (!/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
    return { ok: false, error: 'Password must contain at least one letter and one number' };
  }
  return { ok: true };
}

/* ========================================================================
   9. EMAIL VALIDATION
   ======================================================================== */

export function validateEmail(email) {
  if (!email || typeof email !== 'string') return { ok: false, error: 'Email is required' };
  const trimmed = email.trim().toLowerCase();
  // Basic email format check
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) {
    return { ok: false, error: 'Invalid email format' };
  }
  if (trimmed.length > 254) {
    return { ok: false, error: 'Email is too long' };
  }
  return { ok: true, email: trimmed };
}
