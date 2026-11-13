export const VERSION = '0.3.0';
export const PACKAGE_NAME = 'lightdrawer-mcp';
export const DEFAULT_ORIGIN = 'https://lightdrawer.org';
// Reserved for a future open, rate-limited stamp lane on lightdrawer.org.
// Keyless clients already POST only the hash here so that lane can ship
// later with zero config change. Today the path 404s.
export const MCP_STAMP_PATH = '/api/mcp/stamp';
export const MCP_STAMP_TIMEOUT_MS = 5000;

export function origin() {
  const raw = String(process.env.LIGHTDRAWER_URL || process.env.LIGHTDRAWER_ORIGIN || DEFAULT_ORIGIN).trim();
  return raw.replace(/\/+$/, '') || DEFAULT_ORIGIN;
}

/** True when a non-empty stamp key is configured. Never returns the key itself. */
export function stampKeyConfigured() {
  return !!getStampKey();
}

/**
 * Return the configured stamp key, or null.
 * Callers must not log, print, or include this value in tool output.
 */
export function getStampKey() {
  const raw = process.env.LIGHTDRAWER_STAMP_KEY;
  if (raw == null) return null;
  const trimmed = String(raw).trim();
  return trimmed || null;
}
