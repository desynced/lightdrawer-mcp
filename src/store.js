// Local, private copies of exactly what was hashed at stamp time.
// Nothing here is uploaded. There is no size cap: a partial copy cannot be
// verified later, and the saved bytes are the same size as the original.
import { randomBytes } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { chmod, mkdir, open, readFile, readdir, rename, rm, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { normalizeHash, sha256File, utf8Bytes } from './hash.js';

export const STAMP_META_NAME = 'stamp.json';
export const STAMP_RECEIPT_NAME = 'receipt.zip';

export function saveOriginalsEnabled() {
  const raw = process.env.LIGHTDRAWER_SAVE_ORIGINALS;
  if (raw == null || String(raw).trim() === '') return true;
  return !['0', 'false', 'off', 'no'].includes(String(raw).trim().toLowerCase());
}

export function stampsRootDir() {
  const raw = process.env.LIGHTDRAWER_STAMPS_DIR;
  if (raw != null && String(raw).trim()) return String(raw).trim();
  return join(homedir(), '.lightdrawer', 'stamps');
}

export function stampDirForHash(hash) {
  const h = normalizeHash(hash);
  if (!h) return null;
  return join(stampsRootDir(), h);
}

export function safeOriginalName(source, filePath) {
  if (source === 'text') return 'text.txt';
  let base = String(filePath || 'file').replace(/\\/g, '/');
  const parts = base.split('/');
  base = (parts[parts.length - 1] || '').replace(/\0/g, '');
  if (!base || base === '.' || base === '..' || base.includes('..')) return 'file.bin';
  if (/[\\/]/.test(base)) return 'file.bin';
  return base;
}

function assertInside(parent, child) {
  const root = resolve(parent);
  const target = resolve(child);
  const prefix = root.endsWith(sep) ? root : root + sep;
  if (target !== root && !target.startsWith(prefix)) {
    throw new Error('Refusing to write outside the stamp folder.');
  }
}

async function ensurePrivateDir(dir) {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  try { await chmod(dir, 0o700); } catch { /* not supported on some systems */ }
}

async function atomicWriteFile(dest, bytes) {
  const dir = dirname(dest);
  const tmp = join(dir, `.tmp.${randomBytes(8).toString('hex')}`);
  assertInside(dir, tmp);
  assertInside(dir, dest);
  let fh;
  try {
    fh = await open(tmp, 'w', 0o600);
    await fh.writeFile(bytes);
    await fh.sync();
    await fh.close();
    fh = null;
    await rename(tmp, dest);
    try { await chmod(dest, 0o600); } catch { /* ignore */ }
  } catch (err) {
    if (fh) try { await fh.close(); } catch { /* ignore */ }
    try { await rm(tmp, { force: true }); } catch { /* ignore */ }
    throw err;
  }
}

async function atomicCopyFile(src, dest) {
  const dir = dirname(dest);
  const tmp = join(dir, `.tmp.${randomBytes(8).toString('hex')}`);
  assertInside(dir, tmp);
  assertInside(dir, dest);
  let fh;
  try {
    fh = await open(tmp, 'w', 0o600);
    const reader = createReadStream(src);
    for await (const chunk of reader) {
      await fh.write(chunk);
    }
    await fh.sync();
    await fh.close();
    fh = null;
    await rename(tmp, dest);
    try { await chmod(dest, 0o600); } catch { /* ignore */ }
  } catch (err) {
    if (fh) try { await fh.close(); } catch { /* ignore */ }
    try { await rm(tmp, { force: true }); } catch { /* ignore */ }
    throw err;
  }
}

export async function writeStampRecord(dir, data) {
  const dest = join(dir, STAMP_META_NAME);
  assertInside(dir, dest);
  const body = Buffer.from(`${JSON.stringify(data, null, 2)}\n`, 'utf8');
  await atomicWriteFile(dest, body);
  return dest;
}

export async function readStampRecord(dir) {
  try {
    return JSON.parse(await readFile(join(dir, STAMP_META_NAME), 'utf8'));
  } catch {
    return null;
  }
}

export async function saveOriginal({ hash, source, file, text }) {
  if (!saveOriginalsEnabled()) return { saved: false, skipped: 'disabled' };
  const h = normalizeHash(hash);
  if (!h) throw new Error('hash must be a 64-character SHA-256 hex string.');
  const root = stampsRootDir();
  const dir = join(root, h);
  await ensurePrivateDir(root);
  const parent = dirname(root);
  if (parent.endsWith(`${sep}.lightdrawer`) || parent.endsWith('/.lightdrawer')) {
    try { await chmod(parent, 0o700); } catch { /* ignore */ }
  }
  await ensurePrivateDir(dir);

  const name = safeOriginalName(source, file);
  const dest = join(dir, name);
  assertInside(dir, dest);

  let reused = false;
  try {
    const info = await stat(dest);
    if (info.isFile()) {
      const existing = await sha256File(dest);
      if (existing !== h) throw new Error('A different file already exists in this stamp folder.');
      reused = true;
    }
  } catch (err) {
    if (!err || err.code !== 'ENOENT') throw err;
  }

  if (!reused) {
    if (source === 'text') {
      await atomicWriteFile(dest, utf8Bytes(text));
    } else {
      if (!file) throw new Error('Provide a file path to save a file copy.');
      await atomicCopyFile(file, dest);
    }
    const check = await sha256File(dest);
    if (check !== h) {
      try { await rm(dest, { force: true }); } catch { /* ignore */ }
      throw new Error('The saved copy did not match the fingerprint. The copy was removed.');
    }
  }

  return { saved: true, reused, hash: h, directory: dir, path: dest, name };
}

export async function saveStampMeta({ hash, source, file, stampedVia, receiptUrl, handoff }) {
  const dir = stampDirForHash(hash);
  if (!dir) return null;
  try {
    const info = await stat(dir);
    if (!info.isDirectory()) return null;
  } catch {
    return null;
  }
  const meta = {
    hash: normalizeHash(hash),
    saved_at: new Date().toISOString(),
    source,
    name: safeOriginalName(source, file),
    original_path: source === 'file' ? String(file) : null,
    stamped_via: stampedVia || null,
    receipt_url: receiptUrl || null,
  };
  if (handoff) meta.handoff = handoff;
  await writeStampRecord(dir, meta);
  return meta;
}

export async function saveReceiptCopy(hash, receiptPath) {
  if (!saveOriginalsEnabled()) return { saved: false, skipped: 'disabled' };
  const dir = stampDirForHash(hash);
  if (!dir) return { saved: false };
  try {
    const info = await stat(dir);
    if (!info.isDirectory()) return { saved: false, skipped: 'no_stamp_folder' };
  } catch {
    return { saved: false, skipped: 'no_stamp_folder' };
  }
  const dest = join(dir, STAMP_RECEIPT_NAME);
  assertInside(dir, dest);
  try {
    const info = await stat(dest);
    if (info.isFile()) return { saved: false, reused: true, path: dest };
  } catch (err) {
    if (!err || err.code !== 'ENOENT') throw err;
  }
  await atomicCopyFile(receiptPath, dest);
  return { saved: true, path: dest };
}

export async function findSavedStamp(hash) {
  const h = normalizeHash(hash);
  if (!h) return null;
  const dir = join(stampsRootDir(), h);
  try {
    const info = await stat(dir);
    if (!info.isDirectory()) return null;
  } catch {
    return null;
  }
  const meta = await readStampRecord(dir);
  const preferred = meta && meta.name ? [meta.name] : [];
  const skip = new Set([STAMP_META_NAME, STAMP_RECEIPT_NAME]);
  const names = [...preferred];
  try {
    for (const ent of await readdir(dir, { withFileTypes: true })) {
      if (!ent.isFile() || skip.has(ent.name) || ent.name.startsWith('.tmp.')) continue;
      names.push(ent.name);
    }
  } catch { /* ignore */ }

  let originalPath = null;
  let originalName = null;
  let matches = null;
  const seen = new Set();
  for (const name of names) {
    if (seen.has(name)) continue;
    seen.add(name);
    const p = join(dir, name);
    try {
      const info = await stat(p);
      if (!info.isFile()) continue;
      const got = await sha256File(p);
      originalPath = p;
      originalName = name;
      matches = got === h;
      if (matches) break;
    } catch { /* next */ }
  }

  let receiptPath = null;
  try {
    const rp = join(dir, STAMP_RECEIPT_NAME);
    if ((await stat(rp)).isFile()) receiptPath = rp;
  } catch { /* none */ }

  return {
    found: true,
    hash: h,
    directory: dir,
    original_path: originalPath,
    original_name: originalName,
    matches,
    receipt_path: receiptPath,
    meta,
  };
}
