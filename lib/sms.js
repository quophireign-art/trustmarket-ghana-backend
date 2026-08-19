// backend/lib/sms.js
// SMS gateway for delivery OTP codes, order alerts, and susu reminders —
// the "SMS Gateway" box in the architecture diagram.
//
// Uses Arkesel (https://arkesel.com) — the most widely used SMS API for
// Ghanaian numbers, cheap local rates, no international routing needed.
// Get an API key from https://sms.arkesel.com/user/settings/api-key and set
// ARKESEL_API_KEY (+ optionally ARKESEL_SENDER_ID, max 11 chars, e.g.
// "TrustMrkt") in backend/.env.
//
// If you'd rather use Twilio (e.g. for a diaspora/international user base),
// set TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN / TWILIO_FROM_NUMBER instead —
// this module picks whichever is configured, Arkesel first.

import { randomInt } from 'node:crypto';

const ARKESEL_URL = 'https://sms.arkesel.com/api/v2/sms/send';

function normalizeGhanaNumber(phone) {
  const digits = String(phone || '').replace(/\D/g, '');
  if (digits.startsWith('233')) return `+${digits}`;
  if (digits.startsWith('0')) return `+233${digits.slice(1)}`;
  if (digits.startsWith('+')) return digits;
  return `+233${digits}`;
}

export async function sendSms({ to, message }) {
  const phone = normalizeGhanaNumber(to);

  if (process.env.ARKESEL_API_KEY) {
    const res = await fetch(ARKESEL_URL, {
      method: 'POST',
      headers: {
        'api-key': process.env.ARKESEL_API_KEY,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        sender: process.env.ARKESEL_SENDER_ID || 'TrustMrkt',
        message,
        recipients: [phone.replace('+', '')],
      }),
    });
    const data = await res.json().catch(() => ({}));
    // Arkesel returns numeric string codes: "1000" = success, "1001" = invalid API key, etc.
    // HTTP status is the reliable indicator — don't check data.code for 'ok' (that's not a valid Arkesel code).
    if (!res.ok) {
      console.error('[sms] Arkesel API error:', res.status, JSON.stringify(data));
      const err = new Error(data.message || `Arkesel SMS error (${res.status}, code: ${data.code || 'unknown'})`);
      err.status = 502;
      throw err;
    }
    console.log('[sms] Arkesel SMS sent successfully, code:', data.code, 'to:', phone);
    return { provider: 'arkesel', id: data.data?.[0]?.id, to: phone };
  }

  if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
    const sid = process.env.TWILIO_ACCOUNT_SID;
    const auth = Buffer.from(`${sid}:${process.env.TWILIO_AUTH_TOKEN}`).toString('base64');
    const res = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
      method: 'POST',
      headers: {
        Authorization: `Basic ${auth}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ To: phone, From: process.env.TWILIO_FROM_NUMBER, Body: message }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(data.message || `Twilio SMS error (${res.status})`);
      err.status = 502;
      throw err;
    }
    return { provider: 'twilio', id: data.sid, to: phone };
  }

  const err = new Error(
    'SMS is not configured. Set ARKESEL_API_KEY (recommended for Ghana) or TWILIO_* in backend/.env to enable SMS.'
  );
  err.status = 501;
  throw err;
}

export function generateOtp(length = 6) {
  return String(randomInt(0, 10 ** length)).padStart(length, '0');
}
