// backend/lib/email.js
// "Email Notifications" — real delivery via Resend (simplest modern email
// API, generous free tier, good deliverability). Set RESEND_API_KEY and
// EMAIL_FROM (must be a domain you've verified in Resend) in backend/.env.
// https://resend.com/docs/api-reference/emails/send-email
//
// Without a key, falls back to the original stub behaviour (log + save to
// the sent_emails table) so the app never crashes in local dev.
import * as db from './db.js';

export async function sendEmail({ to, subject, body }) {
  const apiKey = process.env.RESEND_API_KEY;

  if (!apiKey) {
    db.logSentEmail({ to, subject, body });
    console.log(`[email:stub] to=${to} subject="${subject}"`);
    return { success: true, delivered: false, note: 'Email logged (stub) — set RESEND_API_KEY in backend/.env for real delivery.' };
  }

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: process.env.EMAIL_FROM || 'Tiko <notifications@tikogh.com>',
      to,
      subject,
      html: body,
    }),
  });
  const data = await res.json().catch(() => ({}));
  db.logSentEmail({ to, subject, body });

  if (!res.ok) {
    const err = new Error(data.message || `Resend error (${res.status})`);
    err.status = 502;
    throw err;
  }
  return { success: true, delivered: true, id: data.id };
}
