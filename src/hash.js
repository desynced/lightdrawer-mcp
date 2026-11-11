import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';

export const HEX64_RE = /^[0-9a-f]{64}$/;

export function normalizeHash(raw) {
  if (raw == null) return null;
  let s = String(raw).trim().toLowerCase();
  if (s.startsWith('sha256:')) s = s.slice('sha256:'.length).trim();
  s = s.replace(/\s+/g, '');
  return HEX64_RE.test(s) ? s : null;
}

export function sha256Bytes(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

export function sha256Text(text) {
  return sha256Bytes(Buffer.from(String(text), 'utf8'));
}

export async function sha256File(filePath) {
  const info = await stat(filePath);
  if (!info.isFile()) throw new Error(`Not a regular file: ${filePath}`);
  const hash = createHash('sha256');
  const stream = createReadStream(filePath);
  for await (const chunk of stream) hash.update(chunk);
  return hash.digest('hex');
}

export async function readFileBytes(filePath) {
  const info = await stat(filePath);
  if (!info.isFile()) throw new Error(`Not a regular file: ${filePath}`);
  return new Uint8Array(await readFile(filePath));
}

export function utf8Bytes(text) {
  return new Uint8Array(Buffer.from(String(text), 'utf8'));
}
