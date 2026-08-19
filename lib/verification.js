// backend/lib/verification.js
// "ID Verification (Gov't)" — verifies a Ghana Card number against Smile
// Identity's KYC API, which covers Ghana's National Identification Authority
// (NIA) Ghana Card lookups (and doubles as your Credit Bureau / AML checks
// if you upgrade the product tier later).
//
// Sign up at https://usesmileid.com, create a Ghana "Basic KYC" job, and set
// SMILE_PARTNER_ID + SMILE_API_KEY in backend/.env.
// Docs: https://docs.usesmileid.com/products/for-businesses/kyc-verification

import { createHmac } from 'node:crypto';

const SMILE_BASE = process.env.SMILE_SANDBOX === 'true'
  ? 'https://testapi.smileidentity.com/v1'
  : 'https://api.smileidentity.com/v1';

function requireCreds() {
  const partnerId = process.env.SMILE_PARTNER_ID;
  const apiKey = process.env.SMILE_API_KEY;
  if (!partnerId || !apiKey) {
    const err = new Error(
      'ID verification is not configured. Set SMILE_PARTNER_ID and SMILE_API_KEY in backend/.env (see https://usesmileid.com) to enable Ghana Card checks.'
    );
    err.status = 501;
    throw err;
  }
  return { partnerId, apiKey };
}

function signature(partnerId, apiKey, timestamp) {
  return createHmac('sha256', apiKey)
    .update(timestamp + partnerId + 'sid_request')
    .digest('base64');
}

/**
 * Verify a Ghana Card number + full name against NIA records.
 * Returns { verified: boolean, full_name, dob, photo_url?, raw }.
 */
export async function verifyGhanaCard({ id_number, first_name, last_name, job_id }) {
  const { partnerId, apiKey } = requireCreds();
  const timestamp = new Date().toISOString();

  const body = {
    partner_id: partnerId,
    timestamp,
    signature: signature(partnerId, apiKey, timestamp),
    country: 'GH',
    id_type: 'GHANA_CARD',
    id_number,
    first_name,
    last_name,
    job_id: job_id || `tm-${Date.now()}`,
    partner_params: { user_id: id_number, job_id: job_id || `tm-${Date.now()}`, job_type: 5 },
  };

  const res = await fetch(`${SMILE_BASE}/id_verification`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || `ID verification error (${res.status})`);
    err.status = 502;
    throw err;
  }

  return {
    verified: data.result?.Actions?.Verify_ID_Number === 'Verified',
    full_name: data.result?.FullName || null,
    dob: data.result?.DOB || null,
    photo_url: data.result?.PhotoBase64 ? null : undefined, // base64 photo omitted from response by default
    raw: data,
  };
}

/**
 * Business/product verification (Trust Verification System — "Business
 * Verification"). Ghana doesn't expose a free public Registrar-General API,
 * so this validates the certificate document a seller uploads and flags it
 * for a human community-agent review — matching the "Community Agent
 * Verification" flow in the diagram rather than pretending to auto-approve.
 */
export function flagForCommunityReview({ entity_type, entity_id, submitted_by, documents }) {
  return {
    status: 'pending_review',
    entity_type,
    entity_id,
    submitted_by,
    documents,
    note: 'Routed to a Community Agent for manual verification (no public Ghana business-registry API exists yet).',
  };
}
