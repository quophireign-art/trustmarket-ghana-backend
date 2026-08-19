// backend/lib/push.js
// "Push Notifications" — web/mobile push via OneSignal (free tier, works for
// PWA installs of this app on Android/iOS home screens and desktop browsers).
// Create an app at https://onesignal.com, then set ONESIGNAL_APP_ID and
// ONESIGNAL_API_KEY (REST API key) in backend/.env.
// Docs: https://documentation.onesignal.com/reference/create-notification

function requireCreds() {
  const appId = process.env.ONESIGNAL_APP_ID;
  const apiKey = process.env.ONESIGNAL_API_KEY;
  if (!appId || !apiKey) {
    const err = new Error(
      'Push notifications are not configured. Set ONESIGNAL_APP_ID and ONESIGNAL_API_KEY in backend/.env.'
    );
    err.status = 501;
    throw err;
  }
  return { appId, apiKey };
}

/** Send to specific users by external_id (use the Tiko user email as the external id when you register the OneSignal player on the frontend). */
export async function sendPush({ external_user_ids, title, message, url, data }) {
  const { appId, apiKey } = requireCreds();
  const res = await fetch('https://onesignal.com/api/v1/notifications', {
    method: 'POST',
    headers: {
      Authorization: `Basic ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      app_id: appId,
      include_aliases: { external_id: external_user_ids },
      target_channel: 'push',
      headings: { en: title },
      contents: { en: message },
      url,
      data,
    }),
  });
  const result = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(result.errors?.join(', ') || `OneSignal error (${res.status})`);
    err.status = 502;
    throw err;
  }
  return result;
}
