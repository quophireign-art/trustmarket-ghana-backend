// backend/server.js
// A small REST + SSE backend that replaces Base44 for this
// project. Run with: node server.js  (Node 18+ required).
//
// Security hardening applied:
//   - Rate limiting on auth endpoints (15 req / 15 min per IP)
//   - General API rate limiting (60 req / min per IP)
//   - Upload rate limiting (10 req / min per IP)
//   - Security headers (CSP, HSTS, X-Frame-Options, etc.)
//   - Dynamic CORS origin validation
//   - Input sanitization (XSS + SQLi pattern logging)
//   - MIME type validation on uploads (blocks .exe, .js, .html, etc.)
//   - Request body size limits per route
//   - Password strength enforcement
//   - Email format validation

import http from 'node:http';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

import * as db from './lib/db.js';
import { hashPassword, verifyPassword, signToken, verifyToken, getBearerToken } from './lib/auth.js';
import { SCHEMAS, applyDefaults, validateRequired } from './lib/schemas.js';
import { bus, publish } from './lib/events.js';
import { invokeLLM } from './lib/llm.js';
import { saveUpload, UPLOADS_DIR } from './lib/uploads.js';
import { sendEmail } from './lib/email.js';
import * as paystack from './lib/paystack.js';
import * as sms from './lib/sms.js';
import * as maps from './lib/maps.js';
import * as verification from './lib/verification.js';
import * as push from './lib/push.js';
import {
  authLimiter,
  apiLimiter,
  uploadLimiter,
  securityHeaders,
  corsHeaders,
  sanitizeInput,
  validateFileUpload,
  requireAdmin,
  validatePasswordStrength,
  validateEmail,
  enforceBodySizeLimit,
} from './lib/security.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
loadDotEnv(path.join(__dirname, '.env'));

const PORT = Number(process.env.PORT || 8787);

function loadDotEnv(file) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const val = trimmed.slice(eq + 1).trim().replace(/^["']|["']$/g, '');
    if (!(key in process.env)) process.env[key] = val;
  }
}

/* ---------------- helpers ---------------- */

function send(res, status, body, extraHeaders = {}) {
  const payload = typeof body === 'string' ? body : JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    ...securityHeaders(),
    ...extraHeaders,
  });
  res.end(payload);
}

// Wrapper that attaches req so send() can include CORS
function sendFor(req) {
  return function _send(res, status, body, extraHeaders = {}) {
    const payload = typeof body === 'string' ? body : JSON.stringify(body);
    const secHeaders = securityHeaders();
    const cors = corsHeaders(req);
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      ...secHeaders,
      ...cors,
      ...extraHeaders,
    });
    res.end(payload);
  };
}

function readRawBody(req, maxBytes = 2 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > maxBytes) {
        const err = new Error(`Request body too large (limit: ${maxBytes / 1024 / 1024}MB)`);
        err.status = 413;
        req.destroy();
        reject(err);
      }
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

async function readJsonBody(req, maxBytes = 2 * 1024 * 1024) {
  const data = await readRawBody(req, maxBytes);
  if (!data) return {};
  const parsed = JSON.parse(data);
  // Sanitize all input strings recursively
  return sanitizeInput(parsed);
}

function currentUser(req, url) {
  const token = getBearerToken(req) || url.searchParams.get('token');
  const payload = token ? verifyToken(token) : null;
  if (!payload) return null;
  const row = db.getUserById(payload.uid);
  return row ? db.sanitizeUser(row) : null;
}

function requireAuth(req, url, res) {
  const user = currentUser(req, url);
  if (!user) {
    sendFor(req)(res, 401, { error: 'Authentication required' });
    return null;
  }
  return user;
}

function publicBaseUrl(req) {
  return process.env.PUBLIC_BACKEND_URL || `http://${req.headers.host}`;
}

/* ---------------- entity helpers ---------------- */

function applySort(records, sort) {
  if (!sort) return records;
  const desc = sort.startsWith('-');
  const field = desc ? sort.slice(1) : sort;
  return [...records].sort((a, b) => {
    const av = a[field];
    const bv = b[field];
    if (av === bv) return 0;
    const cmp = av > bv ? 1 : -1;
    return desc ? -cmp : cmp;
  });
}

function applyLimit(records, limit) {
  const n = Number(limit);
  return Number.isFinite(n) && n > 0 ? records.slice(0, n) : records;
}

function matchesQuery(record, query) {
  if (!query) return true;
  return Object.entries(query).every(([key, val]) => {
    if (val === undefined || val === null) return true;
    if (Array.isArray(val)) return val.includes(record[key]);
    return record[key] === val;
  });
}

function listEntity(entityName, { query, sort, limit } = {}) {
  if (entityName === 'User') {
    let rows = db.listUsers();
    if (query) rows = rows.filter((r) => matchesQuery(r, query));
    rows = applySort(rows, sort);
    return applyLimit(rows, limit);
  }
  let rows = db.listRecords(entityName);
  if (query) rows = rows.filter((r) => matchesQuery(r, query));
  rows = applySort(rows, sort);
  return applyLimit(rows, limit);
}

/* ---------------- request handler ---------------- */

const server = http.createServer(async (req, res) => {
  const send = sendFor(req);
  const url = new URL(req.url, `http://${req.headers.host}`);
  const parts = url.pathname.split('/').filter(Boolean); // e.g. ['api','entities','Product','xyz']

  // ---- CORS preflight ----
  if (req.method === 'OPTIONS') {
    const cors = corsHeaders(req);
    res.writeHead(204, { ...securityHeaders(), ...cors });
    return res.end();
  }

  try {
    // ---- Global API rate limiting ----
    const apiLimit = apiLimiter(req, res);
    if (apiLimit.limited) {
      return send(res, 429, { error: 'Too many requests. Slow down.', retry_after: apiLimit.retryAfter }, {
        'Retry-After': String(apiLimit.retryAfter),
      });
    }

    // Static file serving for uploaded files
    if (req.method === 'GET' && parts[0] === 'uploads') {
      const filePath = path.join(UPLOADS_DIR, parts.slice(1).join('/'));
      if (!filePath.startsWith(UPLOADS_DIR) || !fs.existsSync(filePath)) {
        return send(res, 404, { error: 'Not found' });
      }
      const cors = corsHeaders(req);
      res.writeHead(200, { ...securityHeaders(), ...cors });
      return fs.createReadStream(filePath).pipe(res);
    }

    if (parts[0] !== 'api') return send(res, 404, { error: 'Not found' });

    if (parts[1] === 'health') {
      return send(res, 200, { ok: true, time: new Date().toISOString() });
    }

    // ---- Integration status diagnostic ----
    // GET /api/integrations/status — quickly check which API keys are configured
    if (parts[1] === 'integrations' && parts[2] === 'status') {
      return send(res, 200, {
        paystack: {
          configured: !!(process.env.PAYSTACK_SECRET_KEY),
          key_prefix: process.env.PAYSTACK_SECRET_KEY ? process.env.PAYSTACK_SECRET_KEY.slice(0, 8) + '...' : null,
          note: "Ghana MoMo provider codes: 'mtn', 'vod' (Vodafone Cash / Telecel), 'atl' (AirtelTigo)",
        },
        arkesel_sms: {
          configured: !!(process.env.ARKESEL_API_KEY),
          key_prefix: process.env.ARKESEL_API_KEY ? process.env.ARKESEL_API_KEY.slice(0, 8) + '...' : null,
          sender_id: process.env.ARKESEL_SENDER_ID || 'TrustMrkt',
          note: "Arkesel returns numeric codes (e.g. '1000' for success). HTTP status is the reliable success indicator.",
        },
        twilio_sms: {
          configured: !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN),
        },
        google_maps: {
          configured: !!(process.env.GOOGLE_MAPS_API_KEY),
          key_prefix: process.env.GOOGLE_MAPS_API_KEY ? process.env.GOOGLE_MAPS_API_KEY.slice(0, 8) + '...' : null,
        },
        smtp_email: {
          configured: !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS),
          host: process.env.SMTP_HOST || null,
        },
        smile_identity: {
          configured: !!(process.env.SMILE_ID_PARTNER_ID && process.env.SMILE_ID_API_KEY),
        },
        onesignal_push: {
          configured: !!(process.env.ONESIGNAL_APP_ID && process.env.ONESIGNAL_REST_API_KEY),
        },
        openai_llm: {
          configured: !!(process.env.OPENAI_API_KEY),
        },
      });
    }

    /* ---------- AUTH ---------- */
    if (parts[1] === 'auth') {
      // ---- Auth-specific rate limiting ----
      const authLimit = authLimiter(req, res);
      if (authLimit.limited) {
        return send(res, 429, { error: 'Too many login attempts. Try again later.', retry_after: authLimit.retryAfter }, {
          'Retry-After': String(authLimit.retryAfter),
        });
      }

      if (parts[2] === 'register' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const { email, password, full_name, phone } = body;

        // Validate email format
        const emailCheck = validateEmail(email);
        if (!emailCheck.ok) return send(res, 400, { error: emailCheck.error });

        // Enforce password strength
        const pwCheck = validatePasswordStrength(password);
        if (!pwCheck.ok) return send(res, 400, { error: pwCheck.error });

        if (db.getUserByEmail(emailCheck.email)) return send(res, 409, { error: 'An account with that email already exists' });
        const { hash, salt } = hashPassword(password);
        const user = db.createUser({ email: emailCheck.email, fullName: full_name, phone, role: 'user', passwordHash: hash, passwordSalt: salt });
        db.createRecord('Wallet', applyDefaults('Wallet', { user_email: user.email }), user.email);
        const token = signToken({ uid: user.id });
        return send(res, 201, { user: db.sanitizeUser(user), token });
      }

      if (parts[2] === 'login' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const { email, password } = body;

        // Validate email format
        const emailCheck = validateEmail(email);
        if (!emailCheck.ok) return send(res, 400, { error: emailCheck.error });

        const user = db.getUserByEmail(emailCheck.email);
        if (!user || !verifyPassword(password || '', user.password_hash, user.password_salt)) {
          // Generic error message to prevent user enumeration
          return send(res, 401, { error: 'Invalid email or password' });
        }
        const token = signToken({ uid: user.id });
        return send(res, 200, { user: db.sanitizeUser(user), token });
      }

      if (parts[2] === 'me' && req.method === 'GET') {
        const user = requireAuth(req, url, res);
        if (!user) return;
        return send(res, 200, user);
      }

      if (parts[2] === 'logout' && req.method === 'POST') {
        return send(res, 200, { ok: true });
      }
    }

    /* ---------- INTEGRATIONS ---------- */
    if (parts[1] === 'integrations') {
      const user = requireAuth(req, url, res);
      if (!user) return;

      if (parts[2] === 'upload' && req.method === 'POST') {
        // Upload-specific rate limiting
        const uploadLimit = uploadLimiter(req, res);
        if (uploadLimit.limited) {
          return send(res, 429, { error: 'Too many uploads. Slow down.', retry_after: uploadLimit.retryAfter }, {
            'Retry-After': String(uploadLimit.retryAfter),
          });
        }

        const body = await readJsonBody(req, 15 * 1024 * 1024);
        // Validate file type
        const fileCheck = validateFileUpload(body.file_name, body.content_type);
        if (!fileCheck.ok) return send(res, 400, { error: fileCheck.error });
        const result = saveUpload(body, publicBaseUrl(req));
        return send(res, 200, result);
      }

      if (parts[2] === 'send-email' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const result = await sendEmail(body);
        return send(res, 200, result);
      }

      if (parts[2] === 'invoke-llm' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const result = await invokeLLM(body);
        return send(res, 200, result);
      }

      if (parts[2] === 'send-sms' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const result = await sms.sendSms(body);
        return send(res, 200, result);
      }

      if (parts[2] === 'send-push' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const result = await push.sendPush(body);
        return send(res, 200, result);
      }
    }

    /* ---------- PAYMENTS (Paystack: cards, MTN MoMo, Telecel Cash, bank transfer) ---------- */
    if (parts[1] === 'payments' && parts[2] === 'paystack') {
      // Webhook is called by Paystack itself, not the logged-in user — verify by signature instead of a bearer token.
      if (parts[3] === 'webhook' && req.method === 'POST') {
        const raw = await readRawBody(req, 1 * 1024 * 1024);
        const signature = req.headers['x-paystack-signature'];
        if (!paystack.verifyWebhookSignature(raw, signature)) {
          return send(res, 401, { error: 'Invalid webhook signature' });
        }
        const event = JSON.parse(raw);

        if (event.event === 'charge.success') {
          const { reference, amount, metadata, customer } = event.data;
          const existing = db.listRecords('WalletTransaction').find((t) => t.reference === reference);
          if (!existing) {
            const userEmail = metadata?.user_email || customer?.email;
            if (metadata?.purpose === 'wallet_fund' && userEmail) {
              const wallets = db.listRecords('Wallet').filter((w) => w.user_email === userEmail);
              const wallet = wallets[0];
              const amt = paystack.fromSubunit(amount);
              const newBal = (wallet?.balance || 0) + amt;
              if (wallet) {
                db.updateRecord('Wallet', wallet.id, { balance: newBal, total_funded: (wallet.total_funded || 0) + amt });
              } else {
                db.createRecord('Wallet', applyDefaults('Wallet', { user_email: userEmail, balance: amt, total_funded: amt }), userEmail);
              }
              const tx = db.createRecord(
                'WalletTransaction',
                applyDefaults('WalletTransaction', {
                  user_email: userEmail, type: 'fund', amount: amt,
                  description: 'Wallet funded via Paystack', payment_method: 'paystack', reference, status: 'completed',
                }),
                userEmail
              );
              publish('WalletTransaction', 'create', tx);
              publish('Wallet', 'update', wallet || {});
            } else if (metadata?.purpose === 'order_payment' && metadata?.order_id) {
              const order = db.updateRecord('Order', metadata.order_id, { payment_status: 'paid', payment_reference: reference, status: 'confirmed' });
              if (order) publish('Order', 'update', order);
            }
          }
        }
        return send(res, 200, { received: true });
      }

      const user = requireAuth(req, url, res);
      if (!user) return;

      // Start a hosted checkout (card / mobile money / bank transfer) for a wallet top-up or order.
      if (parts[3] === 'initialize' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const reference = body.reference || `TM-${Date.now()}-${randomUUID().slice(0, 8)}`;
        const result = await paystack.initializeTransaction({
          email: user.email,
          amountGHS: body.amount,
          reference,
          callback_url: body.callback_url,
          metadata: { user_email: user.email, purpose: body.purpose || 'wallet_fund', order_id: body.order_id },
        });
        return send(res, 200, result);
      }

      // Charge MTN MoMo / Telecel / AirtelTigo directly (no redirect) — Wallet.jsx "Fund" flow.
      if (parts[3] === 'charge-momo' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const reference = body.reference || `TM-${Date.now()}-${randomUUID().slice(0, 8)}`;
        const result = await paystack.chargeMobileMoney({
          email: user.email,
          amountGHS: body.amount,
          phone: body.phone,
          provider: body.provider, // 'mtn' | 'vod' | 'atl'  — 'vod' = Vodafone Cash / Telecel (NOT 'tgo')
          reference,
        });
        return send(res, 200, { ...result, reference });
      }

      if (parts[3] === 'submit-otp' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const result = await paystack.submitMobileMoneyOtp(body);
        return send(res, 200, result);
      }

      // Poll/confirm a transaction after redirect back from checkout or after a direct charge.
      if (parts[3] === 'verify' && parts[4] && req.method === 'GET') {
        const result = await paystack.verifyTransaction(parts[4]);
        if (result.status === 'success') {
          const meta = result.metadata || {};
          const existing = db.listRecords('WalletTransaction').find((t) => t.reference === parts[4]);
          if (!existing && meta.purpose === 'wallet_fund') {
            const wallets = db.listRecords('Wallet').filter((w) => w.user_email === user.email);
            const wallet = wallets[0];
            const amt = paystack.fromSubunit(result.amount);
            const newBal = (wallet?.balance || 0) + amt;
            if (wallet) {
              db.updateRecord('Wallet', wallet.id, { balance: newBal, total_funded: (wallet.total_funded || 0) + amt });
            } else {
              db.createRecord('Wallet', applyDefaults('Wallet', { user_email: user.email, balance: amt, total_funded: amt }), user.email);
            }
            const tx = db.createRecord(
              'WalletTransaction',
              applyDefaults('WalletTransaction', {
                user_email: user.email, type: 'fund', amount: amt,
                description: 'Wallet funded via Paystack', payment_method: 'paystack', reference: parts[4], status: 'completed',
              }),
              user.email
            );
            publish('WalletTransaction', 'create', tx);
          }
        }
        return send(res, 200, result);
      }

      // Register a seller/rider's payout destination (bank account or mobile money wallet).
      if (parts[3] === 'recipient' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const result = await paystack.createTransferRecipient(body);
        db.createRecord('PaystackRecipient', { user_email: user.email, recipient_code: result.recipient_code, type: body.type, account_number: body.account_number }, user.email);
        return send(res, 200, result);
      }

      if (parts[3] === 'resolve-account' && req.method === 'GET') {
        const result = await paystack.resolveAccount({
          account_number: url.searchParams.get('account_number'),
          bank_code: url.searchParams.get('bank_code'),
        });
        return send(res, 200, result);
      }

      if (parts[3] === 'banks' && req.method === 'GET') {
        const result = await paystack.listBanks();
        return send(res, 200, result);
      }

      // Escrow release: pay out a seller/rider once a delivery is confirmed. Admin-only.
      if (parts[3] === 'transfer' && req.method === 'POST') {
        const adminCheck = requireAdmin(user);
        if (!adminCheck.ok) return send(res, adminCheck.status, { error: adminCheck.error });
        const body = await readJsonBody(req);
        const reference = body.reference || `TMOUT-${Date.now()}-${randomUUID().slice(0, 8)}`;
        const result = await paystack.initiateTransfer({ ...body, reference });
        return send(res, 200, { ...result, reference });
      }
    }

    /* ---------- ID VERIFICATION (Ghana Card / KYC) ---------- */
    if (parts[1] === 'verification') {
      const user = requireAuth(req, url, res);
      if (!user) return;

      if (parts[2] === 'ghana-card' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const result = await verification.verifyGhanaCard(body);
        db.updateUser(user.id, { id_verified: result.verified });
        return send(res, 200, result);
      }

      if (parts[2] === 'face' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const hasSmile = !!process.env.SMILE_PARTNER_ID;
        if (hasSmile && body.selfie_url && body.ghana_card_url) {
          try {
            const result = await verification.verifyFaceMatch(body);
            return send(res, 200, result);
          } catch (e) {
            return send(res, 200, { verified: false, review_required: true, message: e.message });
          }
        }
        db.createRecord('AgentActivityLog', {
          agent_email: user.email,
          action: 'verification_step',
          details: 'Face capture submitted for manual review',
          metadata: { selfie_url: body.selfie_url, ghana_card_url: body.ghana_card_url },
          created_date: new Date().toISOString(),
        }, user.email);
        return send(res, 200, { verified: false, review_required: true, message: 'Face capture submitted for manual review.' });
      }

      if (parts[2] === 'community-review' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const result = verification.flagForCommunityReview({ ...body, submitted_by: user.email });
        return send(res, 200, result);
      }

      // Phone OTP for delivery confirmation, account verification, etc.
      if (parts[2] === 'send-otp' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const code = sms.generateOtp();
        db.createRecord('OtpCode', { purpose: body.purpose || 'general', phone: body.phone, code, user_email: user.email, expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(), used: false }, user.email);
        await sms.sendSms({ to: body.phone, message: `Your Tiko verification code is ${code}. It expires in 10 minutes.` });
        return send(res, 200, { sent: true });
      }

      if (parts[2] === 'verify-otp' && req.method === 'POST') {
        const body = await readJsonBody(req);
        const records = db.listRecords('OtpCode').filter((r) => r.phone === body.phone && r.purpose === (body.purpose || 'general') && !r.used);
        const match = records.sort((a, b) => (a.created_date < b.created_date ? 1 : -1))[0];
        const valid = match && match.code === body.code && new Date(match.expires_at) > new Date();
        if (valid) db.updateRecord('OtpCode', match.id, { used: true });
        return send(res, 200, { valid: !!valid });
      }
    }

    /* ---------- MAPS & GPS ---------- */
    if (parts[1] === 'maps') {
      const user = requireAuth(req, url, res);
      if (!user) return;

      if (parts[2] === 'geocode' && req.method === 'GET') {
        const result = await maps.geocodeAddress(url.searchParams.get('address'));
        return send(res, 200, result);
      }

      if (parts[2] === 'reverse-geocode' && req.method === 'GET') {
        const result = await maps.reverseGeocode(url.searchParams.get('lat'), url.searchParams.get('lng'));
        return send(res, 200, result);
      }

      if (parts[2] === 'distance' && req.method === 'GET') {
        const result = await maps.distanceAndEta({
          originLat: url.searchParams.get('origin_lat'),
          originLng: url.searchParams.get('origin_lng'),
          destLat: url.searchParams.get('dest_lat'),
          destLng: url.searchParams.get('dest_lng'),
        });
        return send(res, 200, { ...result, delivery_fee: maps.calculateDeliveryFee(result.distance_km) });
      }
    }

    /* ---------- ENTITIES ---------- */
    if (parts[1] === 'entities' && parts[2]) {
      const entityName = parts[2];
      if (entityName !== 'User' && !SCHEMAS[entityName]) {
        return send(res, 404, { error: `Unknown entity "${entityName}"` });
      }

      // SSE subscribe: GET /api/entities/:name/stream
      if (parts[3] === 'stream' && req.method === 'GET') {
        const user = currentUser(req, url);
        if (!user) return send(res, 401, { error: 'Authentication required' });
        const cors = corsHeaders(req);
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          Connection: 'keep-alive',
          ...securityHeaders({ 'Content-Security-Policy': undefined, 'X-Frame-Options': undefined }), // relax for SSE
          ...cors,
        });
        res.write(': connected\n\n');
        const onEvent = (evt) => res.write(`data: ${JSON.stringify(evt)}\n\n`);
        bus.on(entityName, onEvent);
        const keepAlive = setInterval(() => res.write(': ping\n\n'), 25000);
        req.on('close', () => {
          clearInterval(keepAlive);
          bus.off(entityName, onEvent);
        });
        return;
      }

      // POST /api/entities/:name/filter  { query, sort, limit }
      if (parts[3] === 'filter' && req.method === 'POST') {
        const user = requireAuth(req, url, res);
        if (!user) return;
        const body = await readJsonBody(req);
        return send(res, 200, listEntity(entityName, body));
      }

      // GET /api/entities/:name  (list)  ?sort=&limit=
      if (!parts[3] && req.method === 'GET') {
        const user = requireAuth(req, url, res);
        if (!user) return;
        return send(res, 200, listEntity(entityName, { sort: url.searchParams.get('sort'), limit: url.searchParams.get('limit') }));
      }

      // POST /api/entities/:name  (create)
      if (!parts[3] && req.method === 'POST') {
        const user = requireAuth(req, url, res);
        if (!user) return;
        if (entityName === 'User') {
          return send(res, 405, { error: 'Create users via POST /api/auth/register instead.' });
        }
        const body = await readJsonBody(req);
        const withDefaults = applyDefaults(entityName, body);
        const { ok, missing } = validateRequired(entityName, withDefaults);
        if (!ok) return send(res, 400, { error: `Missing required fields: ${missing.join(', ')}` });
        const record = db.createRecord(entityName, withDefaults, user.email);
        publish(entityName, 'create', record);
        return send(res, 201, record);
      }

      // GET/PUT/PATCH/DELETE /api/entities/:name/:id
      if (parts[3]) {
        const id = parts[3];

        if (req.method === 'GET') {
          const user = requireAuth(req, url, res);
          if (!user) return;
          const record = entityName === 'User' ? db.sanitizeUser(db.getUserById(id)) : db.getRecord(entityName, id);
          if (!record) return send(res, 404, { error: 'Not found' });
          return send(res, 200, record);
        }

        if (req.method === 'PUT' || req.method === 'PATCH') {
          const user = requireAuth(req, url, res);
          if (!user) return;
          const body = await readJsonBody(req);
          const record = entityName === 'User' ? db.sanitizeUser(db.updateUser(id, body)) : db.updateRecord(entityName, id, body);
          if (!record) return send(res, 404, { error: 'Not found' });
          publish(entityName, 'update', record);
          return send(res, 200, record);
        }

        if (req.method === 'DELETE') {
          const user = requireAuth(req, url, res);
          if (!user) return;
          const okDel = entityName === 'User' ? false : db.deleteRecord(entityName, id);
          if (!okDel) return send(res, 404, { error: 'Not found or not deletable' });
          publish(entityName, 'delete', { id });
          return send(res, 200, { id, deleted: true });
        }
      }
    }

    /* ---------- API V1 ALIASES (for frontend marketplace modules) ---------- */
    if (parts[1] === 'v1' && parts[2]) {
      // ---------- multipart/form-data upload (v1 alias) ----------
      if (parts[2] === 'upload' && req.method === 'POST') {
        // Upload-specific rate limiting
        const uploadLimit = uploadLimiter(req, res);
        if (uploadLimit.limited) {
          return send(res, 429, { error: 'Too many uploads. Slow down.', retry_after: uploadLimit.retryAfter }, {
            'Retry-After': String(uploadLimit.retryAfter),
          });
        }

        const user = currentUser(req, url); // optional auth for upload
        const contentType = req.headers['content-type'] || '';
        if (contentType.startsWith('multipart/form-data')) {
          const boundary = contentType.split('boundary=')[1];
          if (!boundary) return send(res, 400, { error: 'Missing multipart boundary' });

          // Enforce body size for multipart uploads (20MB max)
          const rawBuf = await enforceBodySizeLimit(req, 20 * 1024 * 1024).catch((e) => {
            const err = new Error(e.message);
            err.status = 413;
            throw err;
          });

          const raw = rawBuf.toString('latin1');
          const delim = '--' + boundary;
          const parts2 = raw.split(delim).filter((s) => s.trim() && !s.startsWith('--'));
          const results = [];
          for (const part of parts2) {
            const headerEnd = part.indexOf('\r\n\r\n');
            if (headerEnd === -1) continue;
            const header = part.slice(0, headerEnd);
            const bodyRaw = part.slice(headerEnd + 4);
            const bodyTrimmed = bodyRaw.endsWith('\r\n') ? bodyRaw.slice(0, -2) : bodyRaw;
            const nameMatch = header.match(/name="([^"]+)"/);
            const fileMatch = header.match(/filename="([^"]+)"/);
            const fieldName = nameMatch ? nameMatch[1] : 'file';
            if (!fileMatch) continue;
            const fileName = fileMatch[1];

            // SECURITY: Validate file type before saving
            const fileCheck = validateFileUpload(fileName, null);
            if (!fileCheck.ok) {
              results.push({ error: fileCheck.error, file_name: fileName, field: fieldName });
              continue;
            }

            const fileBuf = Buffer.from(bodyTrimmed, 'latin1');
            const content_base64 = fileBuf.toString('base64');
            try {
              const result = saveUpload({ file_name: fileName, content_base64 }, publicBaseUrl(req));
              results.push({ url: result.file_url, file_name: fileName, field: fieldName });
            } catch (e) {
              results.push({ error: e.message, file_name: fileName, field: fieldName });
            }
          }
          if (results.length === 1) {
            return send(res, 200, { url: results[0].url, file_url: results[0].url, file_name: results[0].file_name, results });
          }
          return send(res, 200, { results });
        }
        // JSON upload (original base44Client path)
        const body = await readJsonBody(req, 15 * 1024 * 1024);
        const fileCheck = validateFileUpload(body.file_name, body.content_type);
        if (!fileCheck.ok) return send(res, 400, { error: fileCheck.error });
        const result = saveUpload(body, publicBaseUrl(req));
        return send(res, 200, { url: result.file_url, ...result });
      }

      const entityMap = {
        vehicles: 'Vehicle',
        vehicle: 'Vehicle',
        properties: 'Property',
        property: 'Property',
        mobile: 'Mobile',
        electronics: 'Electronics',
        products: 'Product',
        orders: 'Order',
        users: 'User',
        wallets: 'Wallet',
        buildingmaterials: 'BuildingMaterial',
        buildingmaterial: 'BuildingMaterial',
        buildingservices: 'BuildingService',
        buildingservice: 'BuildingService',
        repairservices: 'RepairService',
        repairservice: 'RepairService',
        manufacturingequipment: 'ManufacturingEquipment',
        manufacturingequipments: 'ManufacturingEquipment',
        manufacturingservices: 'ManufacturingService',
        manufacturingservice: 'ManufacturingService',
        sportsfitness: 'SportsFitness',
        fitness: 'SportsFitness',
        fitnessservices: 'FitnessService',
        fitnessservice: 'FitnessService',
        agriculture: 'Agriculture',
        pets: 'Pet',
        pet: 'Pet',
        jobs: 'Job',
        job: 'Job',
        cvprofiles: 'CVProfile',
        cvprofile: 'CVProfile',
      };
      const entityName = entityMap[parts[2]];
      if (!entityName) return send(res, 404, { error: 'Unknown v1 resource' });
      if (entityName !== 'User' && !SCHEMAS[entityName]) {
        return send(res, 404, { error: `Unknown entity "${entityName}"` });
      }

      // POST /api/v1/:entity (create) — optional auth; use seller_email from body if unauthenticated
      if (!parts[3] && req.method === 'POST') {
        const user = currentUser(req, url);
        const body = await readJsonBody(req);
        const ownerEmail = user ? user.email : (body.seller_email || body.user_email || 'anonymous');
        const withDefaults = applyDefaults(entityName, body);
        const { ok, missing } = validateRequired(entityName, withDefaults);
        if (!ok) return send(res, 400, { error: `Missing required fields: ${missing.join(', ')}` });
        const record = db.createRecord(entityName, withDefaults, ownerEmail);
        publish(entityName, 'create', record);
        return send(res, 201, record);
      }

      // GET /api/v1/:entity (list) — public, no auth required
      if (!parts[3] && req.method === 'GET') {
        return send(res, 200, listEntity(entityName, { sort: url.searchParams.get('sort'), limit: url.searchParams.get('limit') }));
      }

      // GET/PUT/PATCH/DELETE /api/v1/:entity/:id
      if (parts[3]) {
        const id = parts[3];

        // GET single item — public, no auth required
        if (req.method === 'GET') {
          const record = entityName === 'User' ? db.sanitizeUser(db.getUserById(id)) : db.getRecord(entityName, id);
          if (!record) return send(res, 404, { error: 'Not found' });
          return send(res, 200, record);
        }

        // Write operations still require auth
        if (req.method === 'PUT' || req.method === 'PATCH') {
          const user = requireAuth(req, url, res);
          if (!user) return;
          const body = await readJsonBody(req);
          const record = entityName === 'User' ? db.sanitizeUser(db.updateUser(id, body)) : db.updateRecord(entityName, id, body);
          if (!record) return send(res, 404, { error: 'Not found' });
          publish(entityName, 'update', record);
          return send(res, 200, record);
        }

        if (req.method === 'DELETE') {
          const user = requireAuth(req, url, res);
          if (!user) return;
          const okDel = entityName === 'User' ? false : db.deleteRecord(entityName, id);
          if (!okDel) return send(res, 404, { error: 'Not found or not deletable' });
          publish(entityName, 'delete', { id });
          return send(res, 200, { id, deleted: true });
        }
      }
    }

    return send(res, 404, { error: 'Not found' });
  } catch (err) {
    console.error(err);
    // Don't leak internal error details to the client in production
    const message = process.env.NODE_ENV === 'production'
      ? 'Internal server error'
      : (err.message || 'Internal server error');
    return send(res, err.status || 500, { error: message });
  }
});

const HOST = process.env.RENDER ? '0.0.0.0' : 'localhost';

server.listen(PORT, HOST, () => {
  console.log(`Tiko backend listening on http://${HOST}:${PORT}`);
  console.log(`Loaded ${Object.keys(SCHEMAS).length} entity schemas from base44/entities/`);
  console.log(`📦 Database: better-sqlite3 (portable SQLite — works on any Node 18+ host)`);

  const integrations = [
    ['ANTHROPIC_API_KEY', 'AI assistant (shopping AI, negotiation, AI seller assistant)'],
    ['PAYSTACK_SECRET_KEY', 'Payments — cards, MTN MoMo, Telecel Cash, bank transfer, escrow payouts'],
    ['ARKESEL_API_KEY', 'SMS — delivery OTP codes, order/susu alerts'],
    ['GOOGLE_MAPS_API_KEY', 'Maps & GPS — geocoding, rider tracking, delivery fee calc'],
    ['SMILE_PARTNER_ID', 'ID verification — Ghana Card / KYC'],
    ['RESEND_API_KEY', 'Email — real delivery (falls back to console+DB stub)'],
    ['ONESIGNAL_APP_ID', 'Push notifications'],
  ];
  for (const [envVar, label] of integrations) {
    console.log(`  ${process.env[envVar] ? '✅' : '⬜'} ${label}${process.env[envVar] ? '' : ` — set ${envVar} in backend/.env`}`);
  }

  console.log('\n🔒 Security hardening active:');
  console.log('  ✅ Rate limiting (auth: 10/15min, API: 60/min, uploads: 10/min)');
  console.log('  ✅ Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)');
  console.log('  ✅ Dynamic CORS origin validation');
  console.log('  ✅ Input sanitization (XSS pattern stripping, SQLi logging)');
  console.log('  ✅ File upload MIME validation (blocks .exe, .js, .html, .sh, etc.)');
  console.log('  ✅ Request body size limits per route');
  console.log('  ✅ Password strength enforcement (8+ chars, letter + number)');
  console.log('  ✅ Email format validation');
  console.log('  ✅ Admin RBAC middleware for sensitive endpoints');
  console.log('  ✅ Production error message suppression');
});
