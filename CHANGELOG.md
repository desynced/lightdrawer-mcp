# Changelog

Every change to this MCP server that affects what it does or how it is set up is listed here, newest first.

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
