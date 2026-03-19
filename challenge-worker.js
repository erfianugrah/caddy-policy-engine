// PoW Web Worker — SHA-256 hashcash with interleaved nonce search.
// Served at /.well-known/policy-challenge/worker.js by the plugin.
// Each worker gets a starting nonce offset and increments by thread count,
// so N workers collectively search the entire nonce space without overlap.
const encoder = new TextEncoder();

const toHex = (arr) => {
  let s = "";
  for (let i = 0; i < arr.length; i++) s += arr[i].toString(16).padStart(2, "0");
  return s;
};

addEventListener("message", async ({ data: msg }) => {
  const { data, difficulty, nonce: startNonce, threads } = msg;
  let nonce = startNonce;
  const isMainThread = startNonce === 0;
  let iterations = 0;

  const requiredZeroBytes = Math.floor(difficulty / 2);
  const isDifficultyOdd = difficulty % 2 !== 0;

  // Use WebCrypto if available (secure context), otherwise pure-JS fallback.
  const hasWebCrypto = typeof crypto !== "undefined" && crypto.subtle;

  for (;;) {
    const input = data + nonce;
    let hashArray;

    if (hasWebCrypto) {
      const buf = await crypto.subtle.digest("SHA-256", encoder.encode(input));
      hashArray = new Uint8Array(buf);
    } else {
      // Pure-JS SHA-256 fallback (for non-secure contexts / Firefox workers).
      hashArray = sha256Fallback(encoder.encode(input));
    }

    // Check leading zeros at byte level.
    let valid = true;
    for (let i = 0; i < requiredZeroBytes; i++) {
      if (hashArray[i] !== 0) { valid = false; break; }
    }
    if (valid && isDifficultyOdd) {
      if (hashArray[requiredZeroBytes] >> 4 !== 0) valid = false;
    }

    if (valid) {
      postMessage({ hash: toHex(hashArray), data, difficulty, nonce });
      return;
    }

    nonce += threads;
    iterations++;

    // Truncate floating-point drift from large nonce + threads addition.
    if (nonce % 1 !== 0) nonce = Math.trunc(nonce);

    // Main thread sends progress every 1024 iterations.
    if (isMainThread && (iterations & 1023) === 0) {
      postMessage(nonce);
    }
  }
});

// ─── Pure-JS SHA-256 (for environments without WebCrypto) ────────
// Minimal implementation — no dependencies. Only used as fallback.
function sha256Fallback(data) {
  const K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ]);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  const pad = (msg) => {
    const len = msg.length;
    const bitLen = len * 8;
    const padLen = ((56 - (len + 1) % 64) + 64) % 64;
    const buf = new Uint8Array(len + 1 + padLen + 8);
    buf.set(msg);
    buf[len] = 0x80;
    const view = new DataView(buf.buffer);
    view.setUint32(buf.length - 4, bitLen, false);
    return buf;
  };
  const padded = pad(data);
  let [h0,h1,h2,h3,h4,h5,h6,h7] = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  const view = new DataView(padded.buffer);
  for (let off = 0; off < padded.length; off += 64) {
    const w = new Uint32Array(64);
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15]>>>3);
      const s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2]>>>10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0;
    }
    let [a,b,c,d,e,f,g,h] = [h0,h1,h2,h3,h4,h5,h6,h7];
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) | 0;
      const S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h0 = (h0+a)|0; h1 = (h1+b)|0; h2 = (h2+c)|0; h3 = (h3+d)|0;
    h4 = (h4+e)|0; h5 = (h5+f)|0; h6 = (h6+g)|0; h7 = (h7+h)|0;
  }
  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  ov.setUint32(0,h0,false); ov.setUint32(4,h1,false); ov.setUint32(8,h2,false); ov.setUint32(12,h3,false);
  ov.setUint32(16,h4,false); ov.setUint32(20,h5,false); ov.setUint32(24,h6,false); ov.setUint32(28,h7,false);
  return out;
}
