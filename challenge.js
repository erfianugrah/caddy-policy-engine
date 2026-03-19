// PoW challenge solver — multi-threaded Web Worker orchestrator.
// Spawns floor(hardwareConcurrency/2) workers with interleaved nonce search.
// Falls back to single-threaded inline computation if Workers are unavailable.
// Embedded in the plugin via go:embed, injected into challenge.html.
(async () => {
  const statusEl = document.getElementById("challenge-status");
  const progressEl = document.getElementById("challenge-progress-inner");
  const data = document.getElementById("challenge-data");
  if (!data) return;

  const config = JSON.parse(data.textContent);
  const { random_data, difficulty, hmac, original_url, timestamp, algorithm } = config;

  const likelihood = Math.pow(16, -difficulty);
  const t0 = Date.now();

  // ── Submit solution to verify endpoint ──────────────────────────
  const submitSolution = async (hash, nonce) => {
    if (statusEl) statusEl.textContent = "Verified! Redirecting...";
    if (progressEl) progressEl.style.width = "100%";

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
      const loc = resp.headers.get("Location");
      window.location.replace(loc || original_url || "/");
    } else {
      if (statusEl) statusEl.textContent = "Challenge failed. Please refresh the page.";
    }
  };

  // ── Try multi-threaded Web Workers ──────────────────────────────
  const canUseWorkers = typeof Worker !== "undefined";
  const cores = navigator.hardwareConcurrency || 1;
  const threads = Math.max(Math.floor(cores / 2), 1);

  if (canUseWorkers) {
    const algoLabel = (algorithm === "slow") ? "slow mode, " : "";
    if (statusEl) statusEl.textContent = "Computing proof-of-work (" + algoLabel + threads + " threads, difficulty " + difficulty + ")...";
    if (progressEl) progressEl.style.display = "inline-block";

    const workerURL = "/.well-known/policy-challenge/worker.js";
    const workers = [];
    let settled = false;

    const cleanup = () => {
      if (settled) return;
      settled = true;
      workers.forEach(w => w.terminate());
    };

    try {
      await new Promise((resolve, reject) => {
        for (let i = 0; i < threads; i++) {
          const w = new Worker(workerURL);

          w.onmessage = (event) => {
            if (typeof event.data === "number") {
              // Progress update from main thread worker.
              const probability = Math.pow(1 - likelihood, event.data);
              const distance = (1 - probability * probability) * 100;
              if (progressEl) progressEl.style.width = distance + "%";
            } else {
              // Solution found.
              cleanup();
              resolve(event.data);
            }
          };

          w.onerror = (err) => {
            cleanup();
            reject(err);
          };

          w.postMessage({
            data: random_data,
            difficulty: difficulty,
            nonce: i,
            threads: threads,
            algorithm: algorithm || "fast",
          });

          workers.push(w);
        }
      }).then(result => submitSolution(result.hash, result.nonce));
    } catch (e) {
      // Workers failed — fall through to single-threaded.
      if (!settled) {
        cleanup();
        console.warn("Web Workers failed, falling back to single-threaded:", e);
        await solveSingleThreaded();
      }
    }
  } else {
    // No Worker support — single-threaded fallback.
    await solveSingleThreaded();
  }

  // ── Single-threaded fallback (no Workers) ───────────────────────
  async function solveSingleThreaded() {
    if (statusEl) statusEl.textContent = "Computing proof-of-work (difficulty " + difficulty + ")...";
    if (progressEl) progressEl.style.display = "inline-block";

    const encoder = new TextEncoder();
    const requiredZeroBytes = Math.floor(difficulty / 2);
    const isDifficultyOdd = difficulty % 2 !== 0;
    let nonce = 0;

    for (;;) {
      const input = random_data + nonce;
      const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(input));
      const hashArray = new Uint8Array(hashBuffer);

      let valid = true;
      for (let i = 0; i < requiredZeroBytes; i++) {
        if (hashArray[i] !== 0) { valid = false; break; }
      }
      if (valid && isDifficultyOdd) {
        if (hashArray[requiredZeroBytes] >> 4 !== 0) valid = false;
      }

      if (valid) {
        const hash = Array.from(hashArray).map(b => b.toString(16).padStart(2, "0")).join("");
        await submitSolution(hash, nonce);
        return;
      }

      nonce++;
      if ((nonce & 1023) === 0) {
        const probability = Math.pow(1 - likelihood, nonce);
        const distance = (1 - probability * probability) * 100;
        if (progressEl) progressEl.style.width = distance + "%";
      }
    }
  }
})();
