# LightDrawer MCP

A small local [MCP](https://modelcontextprotocol.io) server for [LightDrawer](https://lightdrawer.org). Any MCP client can use it: hash a file or some text on your machine, timestamp that fingerprint, look up a stamp, or check a receipt. Koru is listed first below as the first project this is meant to help.

Your file never leaves your computer. LightDrawer only ever sees a SHA-256 fingerprint — a short unique code of those exact bytes.

LightDrawer itself is the website and Cloudflare Worker at [lightdrawer.org](https://lightdrawer.org). This package is a separate tool that talks to that public site from your machine.

## What you can do

1. **stamp** — fingerprint a local file or some text, then give you a browser link so you can finish on LightDrawer. Open the link, drop the same file, complete the site’s human check, and download your receipt. The recommended link uses `#digest=<hash>`, which stays in the URL fragment and is not sent to any server.
2. **verify** — check a LightDrawer receipt ZIP on your machine, optionally against the original file or text.
3. **lookup** — ask LightDrawer whether it has a public record for a fingerprint, and get the `https://lightdrawer.org/r/<hash>` page.

## Privacy

- Files and text are hashed locally with SHA-256.
- Only that 64-character hash is sent to lightdrawer.org (never the file). Lookup sends it to ask about a record. Stamp may POST it to a reserved future path (see below); if that path is not available, you get a browser link instead.
- Verify runs entirely on your machine and uploads nothing.
- This server does not add AI.

## Install

You need [Node.js](https://nodejs.org) 18 or newer. You do not need to publish or install a package from the npm registry.

```sh
npx -y github:desynced/lightdrawer-mcp
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
      "args": ["-y", "github:desynced/lightdrawer-mcp"]
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
claude mcp add lightdrawer -- npx -y github:desynced/lightdrawer-mcp
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
      "args": ["-y", "github:desynced/lightdrawer-mcp"]
    }
  }
}
```

### Any other MCP client

If the client can start a local stdio server, point it at:

```sh
npx -y github:desynced/lightdrawer-mcp
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

## How stamp works

Stamp fingerprints your file or text on this machine. The file itself is never uploaded.

It then gives you a browser link so you can finish on LightDrawer:

- Recommended: `https://lightdrawer.org/#digest=<hash>` — the hash stays in the URL fragment, so it is not sent to any server.
- Also provided: `https://lightdrawer.org/?expect=<hash>` — same idea, but the hash is in the query string.

Open the link, drop the same file (or a file that contains the exact UTF-8 text), complete the check, and download your receipt.

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
and does a keyless stamp of some text. That stamp POSTs only the hash to the reserved path below (which 404s today), then returns the browser hand-off.

Stamp first POSTs only the hash to `/api/mcp/stamp`. That path is reserved for a future open, rate-limited stamp lane on lightdrawer.org. Today it is not implemented (it 404s), and the tool then falls back to the browser hand-off. When the lane ships, existing installs need no config change. The request body matches `POST /api/stamp`: `{ "digest": "<64-hex>", "tsq": "..." }`.

If LightDrawer has issued you a personal key, set LIGHTDRAWER_STAMP_KEY.

`LIGHTDRAWER_URL` points at a self-hosted LightDrawer instead of `https://lightdrawer.org`.

The verifier under `vendor/` is copied from LightDrawer 1.3.1 (commit `a9ae10f`). See [NOTICE](NOTICE) and [vendor/README.md](vendor/README.md).

## Support

LightDrawer is free and runs on donated time and free public witnesses. If it is useful to you, you can help keep it running at [paypal.me/josephball](https://paypal.me/josephball).

## License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 Joe Ball.
