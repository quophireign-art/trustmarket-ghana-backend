// backend/lib/paystack.js
// Real Paystack integration (Paystack Ghana supports cards, bank transfer,
// and mobile money — MTN MoMo / Telecel Cash / AirtelTigo — under one API,
// which covers "Payment Gateway", "Mobile Money" and "Bank APIs" from the
// architecture diagram with a single provider).
//
// Set PAYSTACK_SECRET_KEY in backend/.env to turn this on. Get test/live
// keys from https://dashboard.paystack.com/#/settings/developer
//
// Docs used: https://paystack.com/docs/payments/accept-payments/
//            https://paystack.com/docs/payments/mobile-money/
//            https://paystack.com/docs/transfers/single-transfers/

import { createHmac } from 'node:crypto';

const PAYSTACK_BASE = 'https://api.paystack.co';

function requireKey() {
  const key = process.env.PAYSTACK_SECRET_KEY;
  if (!key) {
    const err = new Error(
      'Payments are not configured. Set PAYSTACK_SECRET_KEY in backend/.env to enable Paystack.'
    );
    err.status = 501;
    throw err;
  }
  return key;
}

async function paystackFetch(pathName, { method = 'GET', body } = {}) {
  const key = requireKey();
  const res = await fetch(`${PAYSTACK_BASE}${pathName}`, {
    method,
    headers: {
      Authorization: `Bearer ${key}`,
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.status === false) {
    const err = new Error(data.message || `Paystack error (${res.status})`);
    err.status = res.status >= 400 && res.status < 600 ? res.status : 502;
    throw err;
  }
  return data;
}

// GHS amounts must be sent to Paystack in the lowest denomination (pesewas).
export function toSubunit(amountGHS) {
  return Math.round(Number(amountGHS) * 100);
}
export function fromSubunit(amountSubunit) {
  return Number(amountSubunit) / 100;
}

/**
 * Start a payment (card, mobile money, or bank transfer — Paystack's hosted
 * checkout auto-detects which channels to show for a GHS transaction).
 * Returns an `authorization_url` the frontend redirects the user to, plus a
 * `reference` to verify afterwards.
 */
export async function initializeTransaction({ email, amountGHS, reference, callback_url, metadata, channels }) {
  const data = await paystackFetch('/transaction/initialize', {
    method: 'POST',
    body: {
      email,
      amount: toSubunit(amountGHS),
      currency: 'GHS',
      reference,
      callback_url,
      metadata,
      channels: channels || ['card', 'mobile_money', 'bank_transfer'],
    },
  });
  return data.data; // { authorization_url, access_code, reference }
}

/** Charge mobile money directly (no redirect) — MTN, Telecel, or AirtelTigo. */
export async function chargeMobileMoney({ email, amountGHS, phone, provider, reference }) {
  // provider: 'mtn' | 'tgo' (Telecel) | 'atl' (AirtelTigo)
  const data = await paystackFetch('/charge', {
    method: 'POST',
    body: {
      email,
      amount: toSubunit(amountGHS),
      currency: 'GHS',
      reference,
      mobile_money: { phone, provider },
    },
  });
  return data.data; // may include status 'send_otp' / 'pay_offline' / 'success'
}

/** Submit the OTP a mobile money provider texts the customer mid-charge. */
export async function submitMobileMoneyOtp({ otp, reference }) {
  const data = await paystackFetch('/charge/submit_otp', {
    method: 'POST',
    body: { otp, reference },
  });
  return data.data;
}

export async function verifyTransaction(reference) {
  const data = await paystackFetch(`/transaction/verify/${encodeURIComponent(reference)}`);
  return data.data; // { status: 'success'|'failed'|'abandoned', amount, currency, ... }
}

/** Resolve a Ghanaian bank/mobile-money account name before creating a payout recipient (fraud check). */
export async function resolveAccount({ account_number, bank_code }) {
  const data = await paystackFetch(
    `/bank/resolve?account_number=${encodeURIComponent(account_number)}&bank_code=${encodeURIComponent(bank_code)}`
  );
  return data.data; // { account_number, account_name }
}

export async function listBanks() {
  const data = await paystackFetch('/bank?country=ghana&currency=GHS');
  return data.data; // includes mobile money "banks" (MTN, Telecel, AirtelTigo) on Paystack GH
}

/** Create a transfer recipient (seller/rider payout destination) — bank or mobile money. */
export async function createTransferRecipient({ name, account_number, bank_code, type = 'mobile_money' }) {
  const data = await paystackFetch('/transferrecipient', {
    method: 'POST',
    body: {
      type, // 'mobile_money' or 'nuban' (bank account)
      name,
      account_number,
      bank_code,
      currency: 'GHS',
    },
  });
  return data.data; // { recipient_code, ... }
}

/**
 * Release escrowed funds to a seller/rider — this is the "Release Money to
 * Seller" step in the escrow flow. Requires transfers to be enabled on the
 * Paystack account (and, in live mode, OTP/finalize depending on account
 * settings — see finalizeTransfer below).
 */
export async function initiateTransfer({ amountGHS, recipient_code, reason, reference }) {
  const data = await paystackFetch('/transfer', {
    method: 'POST',
    body: {
      source: 'balance',
      amount: toSubunit(amountGHS),
      recipient: recipient_code,
      reason,
      reference,
    },
  });
  return data.data; // { status: 'success'|'pending'|'otp', transfer_code, ... }
}

export async function finalizeTransfer({ transfer_code, otp }) {
  const data = await paystackFetch('/transfer/finalize_transfer', {
    method: 'POST',
    body: { transfer_code, otp },
  });
  return data.data;
}

/** Verify the X-Paystack-Signature header on incoming webhooks (HMAC SHA512 of the raw body). */
export function verifyWebhookSignature(rawBody, signatureHeader) {
  const key = process.env.PAYSTACK_SECRET_KEY;
  if (!key || !signatureHeader) return false;
  const hash = createHmac('sha512', key).update(rawBody).digest('hex');
  return hash === signatureHeader;
}
