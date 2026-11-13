# LightDrawer MCP

A small local [MCP](https://modelcontextprotocol.io) server for [LightDrawer](https://lightdrawer.org). Any MCP client can use it: hash a file or some text on your machine, timestamp that fingerprint, look up a stamp, or check a receipt. Koru is listed first below as the first project this is meant to help.

Your file never leaves your computer. LightDrawer only ever sees a SHA-256 fingerprint — a short unique code of those exact bytes.

LightDrawer itself is the website and Cloudflare Worker at [lightdrawer.org](https://lightdrawer.org). This package is a separate tool that talks to that public site from your machine.

## What you can do

1. **stamp** — fingerprint a local file or some text and timestamp it with LightDrawer. When the open stamp lane is available, this finishes in one step and returns a receipt link. If the lane is off or full, you get a browser link instead: open it, drop the same file, complete the site’s human check, and download your receipt. A byte-for-byte copy of exactly what was hashed is saved on your computer only when you turn that on, so you can verify later.
2. **verify** — check a LightDrawer receipt ZIP on your machine, or pass just a hash to look up a saved original. If you do not pass the original file or text, the tool will try to find the saved copy automatically.
3. **lookup** — ask LightDrawer whether it has a public record for a fingerprint, and get the `https://lightdrawer.org/r/<hash>` page. If a local saved copy exists, the result mentions it.

## Privacy

- Files and text are hashed locally with SHA-256.
- Only that 64-character hash is sent to lightdrawer.org (never the file). Stamp POSTs it to the open lane; if that lane is off or full, you get a browser link instead.
- A copy of the original is saved only on your computer, and only when `LIGHTDRAWER_SAVE_ORIGINALS` is turned on. It is never uploaded.
- Verify runs entirely on your machine and uploads nothing.
- This server does not add AI.

## Security and what this tool can read

Only the SHA-256 fingerprint leaves this machine. The file or text stays local.

This tool can read local files that you, or the AI client, point it at. After it resolves symlinks, a path is allowed only when it stays under the current working directory, a directory listed in `LIGHTDRAWER_ALLOWED_DIRS`, or the stamps folder. The current working directory is not added when it is your home folder or a filesystem root (`/` on macOS and Linux, or a drive root such as `C:\` on Windows). An entry in `LIGHTDRAWER_ALLOWED_DIRS` that is exactly your home folder or a filesystem root is ignored, and one line is written to stderr without the path. A subfolder of your home folder is fine. If your client starts in your home folder, set `LIGHTDRAWER_ALLOWED_DIRS` to the folders you want stamped. `LIGHTDRAWER_ALLOWED_DIRS` is split on the platform path delimiter (`:` on macOS and Linux, `;` on Windows). Well-known secret locations and file names, such as `~/.ssh`, `.env`, and private keys, are refused even inside an allowed directory.

A copy of the original is saved under `~/.lightdrawer/stamps` only when `LIGHTDRAWER_SAVE_ORIGINALS` is turned on.

To report a problem, see [SECURITY.md](SECURITY.md).

## Install

You need [Node.js](https://nodejs.org) 18 or newer. You do not need to publish or install a package from the npm registry.

```sh
npx -y github:desynced/lightdrawer-mcp#v0.3.1
```

That is also the command your MCP client should run. No API key and no extra environment variables are required.

## Add it to an MCP client

### Koru

[Koru](https://github.com/koruworks/mono) is a local-first workspace that can open coding agents as tabs, and it ships its own MCP server so other tools can read your notes. To give those agents — or any MCP client you use alongside Koru — LightDrawer, add this one entry:

```json
{
  "mcpServers": {
    "lightdrawer": {
      "command": "npx",
      "args": ["-y", "github:desynced/lightdrawer-mcp#v0.3.1"]
    }
  }
}
```

Koru’s public docs do not yet spell out a separate file format for extra MCP servers, so this is the generic snippet those clients already understand.

### Claude Desktop

Add the same `mcpServers` block to:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

### Claude Code

```sh
claude mcp add lightdrawer -- npx -y github:desynced/lightdrawer-mcp#v0.3.1
```

Or put the same `mcpServers` block in a project `.mcp.json` file.

### Cursor

Add the same block to `~/.cursor/mcp.json`, or to `.cursor/mcp.json` in a project.

### VS Code

In `.vscode/mcp.json`:

```json
{
  "servers": {
    "lightdrawer": {
      "command": "npx",
      "args": ["-y", "github:desynced/lightdrawer-mcp#v0.3.1"]
    }
  }
}
```

### Any other MCP client

If the client can start a local stdio server, point it at:

```sh
npx -y github:desynced/lightdrawer-mcp#v0.3.1
```

From a local checkout (useful before you rely on the GitHub install):

```json
{
  "mcpServers": {
    "lightdrawer": {
      "command": "node",
      "args": ["/absolute/path/to/lightdrawer-mcp/src/index.js"]
    }
  }
}
```

## Try it

Once the server is added to your client, you can say things like:

- “stamp my notes.md”
- “verify this receipt”
- “look up this file”

### Koru use cases

Koru is a good fit for two everyday habits:

- **Prove an idea or draft existed on a date.** Stamp a note when you first write it down. Later you can show that that exact text was already there.
- **Stamp named versions.** When a draft becomes v1, then v2, then final, stamp each saved file. Each version has its own fingerprint and its own saved copy.

## How stamp works

Stamp fingerprints your file or text on this machine. The file itself is never uploaded.

When LightDrawer’s open stamp lane is available, the stamp finishes there and you get a receipt link (`https://lightdrawer.org/r/<hash>`). The lane may rate-limit or be switched off. If that happens, the tool falls back to a browser link so you can still finish:

1. Open the link it gives you. The recommended one uses `#digest=<hash>`, which stays in the browser and is not sent to any server.
2. Drop the same file (or a file that contains the exact UTF-8 text).
3. Complete the short human check on the site.
4. Download your receipt.

A second link with `?expect=<hash>` is also provided; that hash is in the query string.

## Why a local copy is saved

Editing a note later changes its fingerprint. Stamping the edited note is a new stamp — it does not prove the old one. The only way to check an earlier stamp is to still have the exact bytes that were hashed.

Saving that copy is off unless you turn it on. Set `LIGHTDRAWER_SAVE_ORIGINALS` to `1`, `true`, `on`, or `yes` to save a byte-for-byte copy of exactly what was hashed, locally only:

- Default folder: `~/.lightdrawer/stamps/<hash>/` (that home folder works on every OS).
- Inside: the original (keeping the file’s own name, or `text.txt` for text), a small `stamp.json` (hash, time, source, original path, how it was stamped, and the receipt link), and the receipt once there is one.
- Change the folder with `LIGHTDRAWER_STAMPS_DIR`.
- Leave `LIGHTDRAWER_SAVE_ORIGINALS` unset, or set it to `0`, `false`, `off`, or `no`, and nothing is saved.

`LIGHTDRAWER_MAX_HASH_BYTES` is the largest file the tool will hash (default `2147483648`, which is 2 GiB). `LIGHTDRAWER_MAX_COPY_BYTES` is the largest file it will copy into the stamps folder (default `67108864`, which is 64 MiB). A file over the copy limit can still be hashed, up to the hash limit, but no local copy is saved. An invalid or empty value falls back to the default. The saved copy is the same size as the original, so keep an eye on disk space.

Copies never leave your computer. LightDrawer does not see them. Back up `~/.lightdrawer/stamps` (or your custom folder) if you care about those files — this tool does not upload them anywhere.

If you finished a stamp in the browser, the receipt you download there cannot be linked automatically. The tool will tell you where the saved original is; keep that receipt with it. When you later verify, pass the receipt, or pass the hash, and the tool will look for the saved original.

Website-made receipts stamp `statement.json` (the file hash plus optional notes), not the file hash alone. Their public `/r/` fingerprint is therefore different. Verify maps those hashes when it can, and says so honestly when a lookup used the statement fingerprint instead of the file’s own hash.

## What verify checks

**verify** reuses LightDrawer’s offline verifier (vendored from [desynced/lightdrawer](https://github.com/desynced/lightdrawer) 1.3.1):

| Checked | Not checked |
| --- | --- |
| The receipt’s `statement.json` is well-formed | Anything about who made the file or whether it was true |
| The original file or text matches, if you supply it | Bitcoin block contents (no online explorer lookup) |
| OpenTimestamps proof structure and any claimed Bitcoin block | Pending OpenTimestamps or certificate-log upgrades |
| FreeTSA RFC 3161 token, using the pinned FreeTSA root | FreeTSA revocation (CRL/OCSP) |
| Certificate Transparency proof, including Let’s Encrypt precertificate SCTs against bundled log keys | C2PA Content Credentials (read only, not validated) |
| A Rekor entry, if the receipt includes one | |

Nothing is uploaded. For online proof upgrades or a Bitcoin explorer check, open `verify.html` from the receipt instead.

## Lookup tips

`https://lightdrawer.org/r/<hash>` is a public page for a fingerprint. For receipts made on the website, `<hash>` is the SHA-256 of `statement.json` inside the receipt, not the file’s own hash.

- Pass `receipt` to read that fingerprint from a receipt ZIP.
- Pass `hash` if you already have it.
- Pass `file` or `text` to hash locally and look up *that* hash (this finds stamps of the file or text itself).

## Development

```sh
npm install
npm test          # hashing, tool behavior, example-receipt verify, mocked network
npm run test:smoke  # speak MCP over stdio; live lookup of the example receipt
```

The smoke test looks up the public example receipt at
`https://lightdrawer.org/r/d83f8a256bfc0c6817290c2af8d63c86370147e2f4e7f6cb7009d6fb7a7f97ad`
and does one keyless stamp of some text. That stamp POSTs only the hash to `/api/mcp/stamp`. The smoke test passes when the open lane returns a receipt, and it also passes when the lane is unavailable and the tool returns the browser hand-off.

Stamp first POSTs only the hash to `/api/mcp/stamp`. The request body matches `POST /api/stamp`: `{ "digest": "<64-hex>", "tsq": "..." }`. If that lane is off, full, or unreachable, the tool falls back to the browser hand-off. Existing installs need no config change when the lane is turned on.

If LightDrawer has issued you a personal key, set `LIGHTDRAWER_STAMP_KEY` (this is optional and not required for the open lane).

`LIGHTDRAWER_URL` points at a self-hosted LightDrawer instead of `https://lightdrawer.org`.

The verifier under `vendor/` is copied from LightDrawer 1.3.1 (commit `a9ae10f`). See [NOTICE](NOTICE) and [vendor/README.md](vendor/README.md).

## Support

LightDrawer is free and runs on donated time and free public witnesses. If it is useful to you, you can help keep it running at [paypal.me/josephball](https://paypal.me/josephball).

## License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 Joe Ball.
