/* Incremental SHA-256 (FIPS 180-4). Used to hash user files in chunks so a
   multi-gigabyte video is never loaded into memory all at once. WebCrypto's
   digest() is not incremental, so this small implementation is inlined into
   verify.html. Results are byte-identical to WebCrypto / Node crypto.
   Small in-memory hashes (statement.json, Merkle nodes, …) still use sha256()
   from 00-util.js (WebCrypto). */
const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
const SHA256_H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const SHA256_FILE_CHUNK = 4 * 1024 * 1024; // 4 MiB
const C2PA_HEAD_BYTES = 16 * 1024 * 1024; // scan only the start of the file for Content Credentials
function sha256Rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
function sha256Compress(h, block) {
  const w = new Uint32Array(64);
  for (let i = 0; i < 16; i++) w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
  for (let i = 16; i < 64; i++) {
    const s0 = sha256Rotr(w[i - 15], 7) ^ sha256Rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
    const s1 = sha256Rotr(w[i - 2], 17) ^ sha256Rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
  }
  let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
  for (let i = 0; i < 64; i++) {
    const S1 = sha256Rotr(e, 6) ^ sha256Rotr(e, 11) ^ sha256Rotr(e, 25);
    const ch = (e & f) ^ (~e & g);
    const temp1 = (hh + S1 + ch + SHA256_K[i] + w[i]) | 0;
    const S0 = sha256Rotr(a, 2) ^ sha256Rotr(a, 13) ^ sha256Rotr(a, 22);
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const temp2 = (S0 + maj) | 0;
    hh = g; g = f; f = e; e = (d + temp1) | 0; d = c; c = b; b = a; a = (temp1 + temp2) | 0;
  }
  h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
  h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
}
function sha256Create() { return { h: SHA256_H0.slice(), buf: new Uint8Array(64), bufLen: 0, bytes: 0n }; }
function sha256Update(ctx, data) {
  if (!data || !data.length) return;
  ctx.bytes += BigInt(data.length);
  let off = 0;
  if (ctx.bufLen) {
    const take = Math.min(64 - ctx.bufLen, data.length);
    ctx.buf.set(data.subarray(0, take), ctx.bufLen);
    ctx.bufLen += take; off += take;
    if (ctx.bufLen === 64) { sha256Compress(ctx.h, ctx.buf); ctx.bufLen = 0; }
  }
  while (off + 64 <= data.length) { sha256Compress(ctx.h, data.subarray(off, off + 64)); off += 64; }
  if (off < data.length) { ctx.buf.set(data.subarray(off)); ctx.bufLen = data.length - off; }
}
function sha256Finish(ctx) {
  const bitLen = ctx.bytes * 8n;
  ctx.buf[ctx.bufLen++] = 0x80;
  if (ctx.bufLen > 56) {
    while (ctx.bufLen < 64) ctx.buf[ctx.bufLen++] = 0;
    sha256Compress(ctx.h, ctx.buf);
    ctx.buf.fill(0); ctx.bufLen = 0;
  }
  while (ctx.bufLen < 56) ctx.buf[ctx.bufLen++] = 0;
  const view = new DataView(ctx.buf.buffer, ctx.buf.byteOffset, 64);
  view.setUint32(56, Number((bitLen >> 32n) & 0xffffffffn));
  view.setUint32(60, Number(bitLen & 0xffffffffn));
  sha256Compress(ctx.h, ctx.buf);
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setUint32(i * 4, ctx.h[i] >>> 0);
  return out;
}
function formatBytes(n) {
  if (n < 1024) return n + ' bytes';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + ' MB';
  return (n / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}
/* Hash a File, Blob, or Uint8Array in chunkSize pieces (default 4 MiB). */
async function sha256Source(source, opts) {
  opts = opts || {};
  const chunkSize = opts.chunkSize || SHA256_FILE_CHUNK;
  const onProgress = opts.onProgress;
  const ctx = sha256Create();
  const report = (done, total) => { if (onProgress) onProgress(done, total); };
  if (source instanceof Uint8Array) {
    const total = source.length;
    for (let i = 0; i < total; i += chunkSize) {
      sha256Update(ctx, source.subarray(i, Math.min(i + chunkSize, total)));
      report(Math.min(i + chunkSize, total), total);
      await Promise.resolve();
    }
    return sha256Finish(ctx);
  }
  const total = source.size;
  if (typeof source.slice === 'function') {
    for (let i = 0; i < total; i += chunkSize) {
      const buf = new Uint8Array(await source.slice(i, Math.min(i + chunkSize, total)).arrayBuffer());
      sha256Update(ctx, buf);
      report(Math.min(i + chunkSize, total), total);
      await Promise.resolve();
    }
    return sha256Finish(ctx);
  }
  throw new Error('sha256Source: expected a File, Blob, or Uint8Array');
}
