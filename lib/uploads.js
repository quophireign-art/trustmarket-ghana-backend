// backend/lib/uploads.js
// Backs base44.integrations.Core.UploadFile(). Accepts a base64-encoded file
// from the browser (the client shim reads File objects with FileReader) and
// writes it to backend/uploads, serving it back at a static URL. Swap this
// for an S3/Cloudinary/R2 upload if you need durable, multi-instance storage.
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const UPLOADS_DIR = path.join(__dirname, '..', 'uploads');
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const SAFE_EXT = /^[a-zA-Z0-9.]{1,20}$/;

export function saveUpload({ file_name, content_base64 }, publicBaseUrl) {
  if (!content_base64) {
    const err = new Error('content_base64 is required');
    err.status = 400;
    throw err;
  }
  const ext = path.extname(file_name || '').slice(0, 20);
  const safeExt = SAFE_EXT.test(ext) ? ext : '';
  const id = randomUUID();
  const finalName = `${id}${safeExt}`;
  const buffer = Buffer.from(content_base64, 'base64');

  const MAX_BYTES = 15 * 1024 * 1024; // 15MB
  if (buffer.length > MAX_BYTES) {
    const err = new Error('File too large (15MB limit)');
    err.status = 413;
    throw err;
  }

  fs.writeFileSync(path.join(UPLOADS_DIR, finalName), buffer);
  return { file_url: `${publicBaseUrl}/uploads/${finalName}` };
}
