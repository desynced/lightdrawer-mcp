import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { inspectAllowedFile, SafeToolError } from './paths.js';

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
  const { resolved } = await inspectAllowedFile(filePath, 'hash');
  const hash = createHash('sha256');
  const stream = createReadStream(resolved);
  try {
    for await (const chunk of stream) hash.update(chunk);
  } catch {
    throw new SafeToolError('Could not read that file.');
  }
  return hash.digest('hex');
}

export async function readFileBytes(filePath) {
  const { resolved } = await inspectAllowedFile(filePath, 'hash');
  try {
    return new Uint8Array(await readFile(resolved));
  } catch {
    throw new SafeToolError('Could not read that file.');
  }
}

export function utf8Bytes(text) {
  return new Uint8Array(Buffer.from(String(text), 'utf8'));
}
