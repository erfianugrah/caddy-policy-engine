// PoW challenge solver — SHA-256 hashcash with leading hex-zero difficulty.
// Single-threaded WebCrypto implementation. Embedded in the plugin via go:embed.
// Compatible with Anubis's proof-of-work verification algorithm.
(async () => {
  const encoder = new TextEncoder();
  const statusEl = document.getElementById("challenge-status");
  const progressEl = document.getElementById("challenge-progress-inner");
  const data = document.getElementById("challenge-data");
  if (!data) return;

  const config = JSON.parse(data.textContent);
  const { random_data, difficulty, hmac, original_url, timestamp } = config;

  if (statusEl) statusEl.textContent = "Computing proof-of-work (difficulty " + difficulty + ")...";

  const requiredZeroBytes = Math.floor(difficulty / 2);
  const isDifficultyOdd = difficulty % 2 !== 0;
  const likelihood = Math.pow(16, -difficulty);
  const t0 = Date.now();
  let nonce = 0;

  for (;;) {
    const input = random_data + nonce;
    const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(input));
    const hashArray = new Uint8Array(hashBuffer);

    // Check leading zeros at byte level (matches Anubis sha256-webcrypto.ts:29-39).
    let valid = true;
    for (let i = 0; i < requiredZeroBytes; i++) {
      if (hashArray[i] !== 0) { valid = false; break; }
    }
    if (valid && isDifficultyOdd) {
      if (hashArray[requiredZeroBytes] >> 4 !== 0) valid = false;
    }

    if (valid) {
      // Convert to hex string for submission.
      const hash = Array.from(hashArray).map(b => b.toString(16).padStart(2, "0")).join("");
      if (statusEl) statusEl.textContent = "Verified! Redirecting...";
      if (progressEl) progressEl.style.width = "100%";

      // Submit to verification endpoint.
      const form = new URLSearchParams();
      form.set("random_data", random_data);
      form.set("nonce", String(nonce));
      form.set("response", hash);
      form.set("hmac", hmac);
      form.set("difficulty", String(difficulty));
      form.set("timestamp", timestamp);
      form.set("original_url", original_url);
      form.set("elapsed_ms", String(Date.now() - t0));

      const resp = await fetch("/.well-known/policy-challenge/verify", {
        method: "POST",
        body: form,
        redirect: "manual",
      });

      if (resp.status === 302 || resp.status === 303 || resp.type === "opaqueredirect") {
        window.location.replace(original_url || "/");
      } else if (resp.ok) {
        // Server might return 200 with Location header or redirect URL in body.
        const loc = resp.headers.get("Location");
        if (loc) {
          window.location.replace(loc);
        } else {
          window.location.replace(original_url || "/");
        }
      } else {
        if (statusEl) statusEl.textContent = "Challenge failed. Please refresh the page.";
      }
      return;
    }

    nonce++;

    // Update progress bar every 1024 iterations.
    if ((nonce & 1023) === 0) {
      const probability = Math.pow(1 - likelihood, nonce);
      const distance = (1 - probability * probability) * 100;
      if (progressEl) progressEl.style.width = distance + "%";
    }
  }
})();
