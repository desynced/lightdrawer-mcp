# Vendored LightDrawer verifier

These files are copied from the LightDrawer repository so this package
can verify receipts offline without being part of that repo.

- Source: https://github.com/desynced/lightdrawer
- Commit: a9ae10f (release 1.3.1)
- License: MIT, Copyright (c) 2026 Joe Ball (same as this package; see ../LICENSE)

| Path | What it is |
| --- | --- |
| `web/lib/*.js` | LightDrawer's receipt core: hashing helpers, ZIP read/write, OpenTimestamps, RFC 3161, Certificate Transparency (including precertificate SCTs), Rekor, C2PA read-only, and `verifyReceipt` |
| `trust/` | Pinned FreeTSA certificates, Let's Encrypt ISRG roots, the Rekor public key, and `ct-logs.json` (CT log keys used to check embedded SCTs) |

Do not edit these copies to change verifier behavior. Refresh them from a
newer LightDrawer release when the verifier itself changes.

The loader in `src/verifier.js` concatenates `web/lib/*.js` and injects
the trust anchors the same way LightDrawer's `scripts/build.mjs` does.
