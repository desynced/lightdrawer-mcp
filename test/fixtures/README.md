# Test fixtures

Copied from LightDrawer (https://github.com/desynced/lightdrawer) release 1.3.1,
commit a9ae10f, `examples/selftest-receipt/`.

- `selftest.txt` — the original sample file
- `selftest.txt.lightdrawer-receipt.zip` — its complete receipt (OpenTimestamps,
  FreeTSA, and certificate-log proof)

The public lookup page for this receipt is:

https://lightdrawer.org/r/d83f8a256bfc0c6817290c2af8d63c86370147e2f4e7f6cb7009d6fb7a7f97ad

That fingerprint is the SHA-256 of `statement.json` inside the ZIP, not of
`selftest.txt` itself. The file hash is
`3eb350df8fb833e57d3ee572bac8c8113c3499c72280dacd85b30bb210e36b4a`.
