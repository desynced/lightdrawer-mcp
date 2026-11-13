# Changelog

Every change to this MCP server that affects what it does or how it is set up is listed here, newest first.

## [0.3.0] - 2026-11-12

### Security
- Stamp, verify, and lookup resolve a path, including symlinks, before they decide whether to read it. A path is allowed only under the current working directory, `LIGHTDRAWER_ALLOWED_DIRS`, or the stamps folder. Secret locations and names such as `~/.ssh`, `.env`, and private keys are refused. The target of a refused symlink is not shown.
- Hash reads stop at `LIGHTDRAWER_MAX_HASH_BYTES` (default 2 GiB). Saved copies stop at `LIGHTDRAWER_MAX_COPY_BYTES` (default 64 MiB). A file over the limit is refused before the hash or the copy starts.
- Saving a local copy is off unless `LIGHTDRAWER_SAVE_ORIGINALS` is set to `1`, `true`, `on`, or `yes`.
- Text taken from a receipt (the subject, notes, filenames, and check details) is marked untrusted and cut to 200 characters so it is not treated as instructions.
- A failed stamp returns a generic error and the HTTP status. Raw upstream error text is not repeated.
- Added `SECURITY.md`. Dependabot checks npm updates weekly on `main`.

### Changed
- The open stamp lane is described without claiming that any cap is on or off. The lane may rate-limit or be switched off, and the tool then falls back to a browser link.
- `@modelcontextprotocol/sdk` is pinned to exact version 1.32.2.
- Install instructions use the pinned tag `v0.3.0`.

## [0.2.0] - 2026-11-10

### Added
- Stamping through LightDrawer's open lane (`POST /api/mcp/stamp`) finishes in one step when the lane is available. If the lane is off, full (HTTP 429), temporarily unavailable (HTTP 503), or unreachable, the tool falls back to a browser link.
- Each stamp saves a byte-for-byte local copy of exactly what was hashed, under `~/.lightdrawer/stamps/<hash>/` by default. The folder holds the original, a small `stamp.json`, and the receipt once there is one. Change the folder with `LIGHTDRAWER_STAMPS_DIR`. Turn saving off with `LIGHTDRAWER_SAVE_ORIGINALS=0`.
- Verify accepts a hash or a receipt and will look for that saved original automatically. Lookup mentions a local copy when one exists.

### Changed
- The stamp tool description now explains the open lane, its limits, the browser fallback, and the local saved copy.

## [0.1.0] - 2026-11-10

### Added
- First public release: a local MCP server with stamp, verify, and lookup tools. Files are hashed on the developer’s machine; only the hash is sent to LightDrawer.
