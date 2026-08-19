// backend/lib/schemas.js
// Reads base44/entities/*.jsonc (the schema files already in this project) so the
// generic entity API knows each entity's required fields and defaults, without
// needing a separate migration step per entity.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ENTITIES_DIR = path.join(__dirname, '..', '..', 'base44', 'entities');

function stripJsonComments(text) {
  // Strips // line comments and /* */ block comments outside of strings.
  let out = '';
  let inString = false;
  let stringChar = '';
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const next = text[i + 1];
    if (inString) {
      out += c;
      if (c === '\\') { out += next; i++; continue; }
      if (c === stringChar) inString = false;
      continue;
    }
    if (c === '"' || c === "'") { inString = true; stringChar = c; out += c; continue; }
    if (c === '/' && next === '/') { while (i < text.length && text[i] !== '\n') i++; out += '\n'; continue; }
    if (c === '/' && next === '*') { i += 2; while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++; i++; continue; }
    out += c;
  }
  return out;
}

function loadSchemas() {
  const map = {};
  if (!fs.existsSync(ENTITIES_DIR)) return map;
  for (const file of fs.readdirSync(ENTITIES_DIR)) {
    if (!file.endsWith('.jsonc') && !file.endsWith('.json')) continue;
    try {
      const raw = fs.readFileSync(path.join(ENTITIES_DIR, file), 'utf8');
      const schema = JSON.parse(stripJsonComments(raw));
      map[schema.name || path.basename(file, path.extname(file))] = schema;
    } catch (err) {
      console.warn(`[schemas] Failed to parse ${file}:`, err.message);
    }
  }
  return map;
}

export const SCHEMAS = loadSchemas();

export function getSchema(entityName) {
  return SCHEMAS[entityName] || null;
}

export function applyDefaults(entityName, data) {
  const schema = getSchema(entityName);
  if (!schema?.properties) return data;
  const out = { ...data };
  for (const [key, def] of Object.entries(schema.properties)) {
    if (out[key] === undefined && def.default !== undefined) {
      out[key] = def.default;
    }
  }
  return out;
}

export function validateRequired(entityName, data) {
  const schema = getSchema(entityName);
  if (!schema?.required) return { ok: true };
  const missing = schema.required.filter((k) => data[k] === undefined || data[k] === null || data[k] === '');
  return missing.length ? { ok: false, missing } : { ok: true };
}
