// Shared path policy for every file or receipt this process reads or copies.
// Resolve with realpath before allow/deny so a symlink cannot point at a secret.
import { realpath, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, delimiter, join, resolve, sep } from 'node:path';

export const PATH_NOT_ALLOWED_MESSAGE = 'That path is not allowed.';
export const DEFAULT_MAX_HASH_BYTES = 2147483648;
export const DEFAULT_MAX_COPY_BYTES = 67108864;

export class SafeToolError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SafeToolError';
  }
}

function readPositiveInt(name, fallback) {
  const raw = process.env[name];
  if (raw == null) return fallback;
  const trimmed = String(raw).trim();
  if (!/^[1-9]\d*$/.test(trimmed)) return fallback;
  const value = Number(trimmed);
  if (!Number.isSafeInteger(value) || value <= 0) return fallback;
  return value;
}

export function maxHashBytes() {
  return readPositiveInt('LIGHTDRAWER_MAX_HASH_BYTES', DEFAULT_MAX_HASH_BYTES);
}

export function maxCopyBytes() {
  return readPositiveInt('LIGHTDRAWER_MAX_COPY_BYTES', DEFAULT_MAX_COPY_BYTES);
}

export function hashTooBigMessage(cap = maxHashBytes()) {
  return `That file is larger than the hash size limit of ${cap} bytes.`;
}

export function copyTooBigMessage(cap = maxCopyBytes()) {
  return `That file is larger than the copy size limit of ${cap} bytes.`;
}

function configuredStampsDir() {
  const raw = process.env.LIGHTDRAWER_STAMPS_DIR;
  if (raw != null && String(raw).trim()) return String(raw).trim();
  return join(homedir(), '.lightdrawer', 'stamps');
}

function pathKey(value) {
  const abs = resolve(value);
  return process.platform === 'win32' ? abs.toLowerCase() : abs;
}

export function isInside(root, target) {
  const base = pathKey(root);
  const child = pathKey(target);
  if (child === base) return true;
  const prefix = base.endsWith(sep) ? base : base + sep;
  return child.startsWith(prefix);
}

export function isSecretBasename(filePath) {
  const base = basename(filePath).toLowerCase();
  if (base === '.env' || base.startsWith('.env.')) return true;
  if (base.startsWith('id_')) return true;
  return /\.(pem|key|p12|pfx)$/.test(base);
}

function secretCandidates(home) {
  return [
    join(home, '.ssh'),
    join(home, '.aws'),
    join(home, '.gnupg'),
    join(home, '.netrc'),
    join(home, '.kube'),
    join(home, '.docker'),
    join(home, '.config', 'google-chrome'),
    join(home, '.config', 'chromium'),
    join(home, '.mozilla', 'firefox'),
    join(home, 'snap', 'chromium'),
    join(home, '.var', 'app', 'com.google.Chrome'),
    join(home, '.var', 'app', 'org.chromium.Chromium'),
    join(home, '.var', 'app', 'org.mozilla.firefox'),
    join(home, 'Library', 'Application Support', 'Google', 'Chrome'),
    join(home, 'Library', 'Application Support', 'Chromium'),
    join(home, 'Library', 'Application Support', 'Firefox'),
    join(home, 'Library', 'Safari'),
    join(home, 'Library', 'Containers', 'com.apple.Safari'),
    join(home, 'AppData', 'Local', 'Google', 'Chrome', 'User Data'),
    join(home, 'AppData', 'Local', 'Chromium', 'User Data'),
    join(home, 'AppData', 'Roaming', 'Mozilla', 'Firefox'),
  ];
}

async function homeDir() {
  try {
    return await realpath(homedir());
  } catch {
    return resolve(homedir());
  }
}

export async function isSecretLocation(resolved) {
  const home = await homeDir();
  for (const candidate of secretCandidates(home)) {
    if (isInside(candidate, resolved)) return true;
    try {
      const real = await realpath(candidate);
      if (real !== candidate && isInside(real, resolved)) return true;
    } catch {
      /* the secret location is not present on this machine */
    }
  }
  return false;
}

async function existingReal(absPath) {
  try {
    return await realpath(absPath);
  } catch {
    return null;
  }
}

async function allowedRoots() {
  const roots = [];
  const cwd = await existingReal(resolve(process.cwd()));
  if (cwd) roots.push(cwd);
  const raw = process.env.LIGHTDRAWER_ALLOWED_DIRS;
  if (raw != null && String(raw).trim()) {
    for (const part of String(raw).split(delimiter)) {
      const entry = part.trim();
      if (!entry) continue;
      const real = await existingReal(resolve(entry));
      if (real) roots.push(real);
    }
  }
  const stamps = await existingReal(resolve(configuredStampsDir()));
  if (stamps) roots.push(stamps);
  return roots;
}

async function isUnderAllowedRoot(resolved) {
  const roots = await allowedRoots();
  return roots.some((root) => isInside(root, resolved));
}

function denyIfSecret(resolved) {
  return isSecretLocation(resolved).then((secretPlace) => {
    if (secretPlace || isSecretBasename(resolved)) {
      throw new SafeToolError(PATH_NOT_ALLOWED_MESSAGE);
    }
  });
}

/**
 * Resolve inputPath with realpath, then allow or deny it.
 * The thrown message never includes the resolved path.
 */
export async function resolveAllowedPath(inputPath) {
  if (inputPath == null || String(inputPath).trim() === '') {
    throw new SafeToolError('Could not read that file.');
  }
  let resolved;
  try {
    resolved = await realpath(inputPath);
  } catch {
    throw new SafeToolError('Could not read that file.');
  }
  await denyIfSecret(resolved);
  if (!(await isUnderAllowedRoot(resolved))) {
    throw new SafeToolError(PATH_NOT_ALLOWED_MESSAGE);
  }
  return resolved;
}

/**
 * Stat a resolved file and refuse it before the caller hashes or copies.
 * kind is "hash" or "copy".
 */
export async function inspectAllowedFile(inputPath, kind) {
  const resolved = await resolveAllowedPath(inputPath);
  let info;
  try {
    info = await stat(resolved);
  } catch {
    throw new SafeToolError('Could not read that file.');
  }
  if (!info.isFile()) throw new SafeToolError('That path is not a regular file.');
  const copy = kind === 'copy';
  const cap = copy ? maxCopyBytes() : maxHashBytes();
  if (info.size > cap) {
    throw new SafeToolError(copy ? copyTooBigMessage(cap) : hashTooBigMessage(cap));
  }
  return { resolved, size: info.size };
}

/**
 * A member of a receipt directory that already passed the path policy.
 * Secret-named files inside the receipt (such as bundled trust certificates)
 * are skipped and never read. A symlink that resolves outside the receipt
 * directory, or into a secret location, is refused.
 */
export async function assessReceiptMember(receiptRoot, memberPath) {
  let resolved;
  try {
    resolved = await realpath(memberPath);
  } catch {
    throw new SafeToolError('Could not read the receipt.');
  }
  if (!isInside(receiptRoot, resolved) || await isSecretLocation(resolved)) {
    throw new SafeToolError(PATH_NOT_ALLOWED_MESSAGE);
  }
  if (isSecretBasename(resolved)) return { action: 'skip', resolved };
  return { action: 'read', resolved };
}
