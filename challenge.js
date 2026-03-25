// PoW challenge solver with browser fingerprint signal collection.
// Multi-threaded Web Worker orchestrator + environment probes + behavioral signals.
// Embedded in the plugin via go:embed, injected into challenge.html.
(async () => {
  const statusEl = document.getElementById("challenge-status");
  const progressEl = document.getElementById("challenge-progress-inner");
  const data = document.getElementById("challenge-data");
  if (!data) return;

  const config = JSON.parse(data.textContent);
  const { random_data, difficulty, hmac, original_url, timestamp, algorithm } = config;

  const t0 = Date.now();

  // Estimate median solve time (ms) for the time-based progress bar.
  // Formula mirrors server-side minSolveMs: 16^difficulty / (cores * hashesPerCoreMs).
  // We use the full expected iterations (not the safety-factored minimum) because
  // this is the median — half of solves finish before this, half after.
  const cores = navigator.hardwareConcurrency || 1;
  const threads = Math.max(Math.floor(cores / 2), 1);
  const hashesPerCoreMs = 50; // generous upper bound, same as server
  const expectedIters = Math.pow(16, difficulty);
  const isSlow = (algorithm === "slow");
  // "slow" algorithm adds 10ms per iteration per thread — completely dominates.
  const estimatedMs = isSlow
    ? (expectedIters / threads) * 10 // 10ms delay per iter, divided across threads
    : expectedIters / (threads * hashesPerCoreMs);
  // Minimum 500ms so the bar is visible even at difficulty 1.
  const estimatedSolveMs = Math.max(estimatedMs, 500);

  // Time-based progress: asymptotic curve that approaches 95% smoothly.
  // Uses 1 - e^(-k*t) where k is tuned so we hit ~80% at the estimated time.
  // This means: fast early progress (reassuring), gradual slowdown, never stalls.
  // If the solve takes longer than estimated, the bar keeps creeping toward 95%.
  const progressK = -Math.log(1 - 0.80) / estimatedSolveMs; // k such that f(estimated) = 0.80
  function timeProgress() {
    const elapsed = Date.now() - t0;
    const pct = (1 - Math.exp(-progressK * elapsed)) * 95;
    return Math.min(pct, 95);
  }

  // ── Layer 3: JS Environment Probes ──────────────────────────────
  // Collected at page load, before PoW starts.
  const signals = {};

  // 3a. Automation markers
  signals.wd = navigator.webdriver ? 1 : 0;
  signals.cdc = (() => {
    try {
      for (const key of Object.keys(document)) {
        if (/^cdc_|^__puppeteer/.test(key)) return 1;
      }
    } catch {}
    return 0;
  })();
  signals.cr = (window.chrome && window.chrome.runtime) ? 1 : 0;

  // 3b. Plugin & feature presence
  signals.plg = navigator.plugins ? navigator.plugins.length : -1;
  signals.lang = navigator.languages ? navigator.languages.length : 0;
  signals.sv = (() => {
    try {
      return window.speechSynthesis ? speechSynthesis.getVoices().length : -1;
    } catch { return -1; }
  })();

  // 3c. WebGL renderer (SwiftShader = headless) + MAX_TEXTURE_SIZE
  signals.wglr = "";
  try {
    const c = document.createElement("canvas");
    const gl = c.getContext("webgl") || c.getContext("experimental-webgl");
    if (gl) {
      const ext = gl.getExtension("WEBGL_debug_renderer_info");
      if (ext) {
        signals.wglr = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || "";
      }
      // MAX_TEXTURE_SIZE catches stealth scripts that patch the renderer
      // string but can't fake GPU limits. SwiftShader caps at 8192.
      signals.wglMaxTex = gl.getParameter(gl.MAX_TEXTURE_SIZE) || 0;
    }
  } catch {}

  // 3c-extra. Audio fingerprint — OfflineAudioContext produces different
  // output per audio driver/OS. Headless Chrome returns deterministic output.
  signals.audioHash = await (async () => {
    try {
      const ctx = new OfflineAudioContext(1, 44100, 44100);
      const osc = ctx.createOscillator();
      osc.type = "triangle";
      osc.frequency.setValueAtTime(10000, ctx.currentTime);
      const comp = ctx.createDynamicsCompressor();
      comp.threshold.setValueAtTime(-50, ctx.currentTime);
      comp.knee.setValueAtTime(40, ctx.currentTime);
      comp.ratio.setValueAtTime(12, ctx.currentTime);
      comp.attack.setValueAtTime(0, ctx.currentTime);
      comp.release.setValueAtTime(0.25, ctx.currentTime);
      osc.connect(comp);
      comp.connect(ctx.destination);
      osc.start(0);
      const rendered = await ctx.startRendering();
      const data = rendered.getChannelData(0).slice(4500, 5000);
      let hash = 0;
      for (let i = 0; i < data.length; i++) {
        hash = ((hash << 5) - hash + Math.round(data[i] * 1000000)) | 0;
      }
      return hash;
    } catch { return 0; }
  })();

  // 3d. Hardware consistency
  signals.cores = navigator.hardwareConcurrency || 0;
  signals.mem = navigator.deviceMemory || 0;
  signals.touch = navigator.maxTouchPoints || 0;
  signals.plt = navigator.platform || "";
  signals.sw = screen.width;
  signals.sh = screen.height;

  // 3e. Permissions API timing (async — done before PoW starts)
  signals.pt = -1;
  try {
    const pt0 = performance.now();
    await navigator.permissions.query({ name: "notifications" });
    signals.pt = Math.round((performance.now() - pt0) * 100) / 100;
  } catch {}

  // ── Layer 4: Behavioral Signals ─────────────────────────────────
  // Collected during PoW computation.
  const behavior = { me: 0, ke: 0, fc: 0, se: 0, fi: -1 };
  const progressTimings = [];
  let lastProgressTs = Date.now();

  const onMouse = () => { behavior.me++; if (behavior.fi < 0) behavior.fi = Date.now() - t0; };
  const onKey = () => { behavior.ke++; if (behavior.fi < 0) behavior.fi = Date.now() - t0; };
  const onFocus = () => behavior.fc++;
  const onScroll = () => { behavior.se++; if (behavior.fi < 0) behavior.fi = Date.now() - t0; };

  document.addEventListener("mousemove", onMouse);
  document.addEventListener("keydown", onKey);
  document.addEventListener("visibilitychange", onFocus);
  document.addEventListener("scroll", onScroll);

  // ── Submit solution to verify endpoint ──────────────────────────
  const submitSolution = async (hash, nonce) => {
    // Remove listeners
    document.removeEventListener("mousemove", onMouse);
    document.removeEventListener("keydown", onKey);
    document.removeEventListener("visibilitychange", onFocus);
    document.removeEventListener("scroll", onScroll);

    if (statusEl) statusEl.textContent = "Verified! Redirecting...";
    if (progressEl) progressEl.style.width = "100%";

    // Compute worker timing variance
    let wtv = 0;
    if (progressTimings.length >= 3) {
      const mean = progressTimings.reduce((a, b) => a + b, 0) / progressTimings.length;
      const variance = progressTimings.reduce((a, b) => a + (b - mean) ** 2, 0) / progressTimings.length;
      wtv = Math.round(Math.sqrt(variance) * 100) / 100;
    }

    const form = new URLSearchParams();
    form.set("random_data", random_data);
    form.set("nonce", String(nonce));
    form.set("response", hash);
    form.set("hmac", hmac);
    form.set("difficulty", String(difficulty));
    form.set("timestamp", timestamp);
    form.set("original_url", original_url);
    form.set("elapsed_ms", String(Date.now() - t0));

    // Signals (compact JSON to minimize form size)
    form.set("signals", JSON.stringify(signals));
    form.set("behavior", JSON.stringify({
      ...behavior,
      wtv: wtv,
      dur: Date.now() - t0,
    }));

    const resp = await fetch("/.well-known/policy-challenge/verify", {
      method: "POST",
      body: form,
      redirect: "manual",
    });

    // Register session tracking service worker before redirecting.
    // The SW will call clients.claim() on activate, so it will control
    // the next page load immediately. Registration is fire-and-forget —
    // we don't wait for it to complete before redirecting.
    if ("serviceWorker" in navigator) {
      navigator.serviceWorker.register(
        "/.well-known/policy-challenge/session-sw.js",
        { scope: "/" }
      ).catch(() => {}); // best-effort — don't block redirect on failure
    }

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

  if (canUseWorkers) {
    if (statusEl) statusEl.textContent = "Verifying your browser...";
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
              // Progress + behavioral timing
              const now = Date.now();
              progressTimings.push(now - lastProgressTs);
              lastProgressTs = now;
              // Time-based progress — smooth asymptotic curve regardless of difficulty.
              if (progressEl) progressEl.style.width = timeProgress() + "%";
            } else {
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
      if (!settled) {
        cleanup();
        console.warn("Web Workers failed, falling back to single-threaded:", e);
        await solveSingleThreaded();
      }
    }
  } else {
    await solveSingleThreaded();
  }

  // ── Single-threaded fallback ────────────────────────────────────
  async function solveSingleThreaded() {
    if (statusEl) statusEl.textContent = "Verifying your browser...";
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
        const now = Date.now();
        progressTimings.push(now - lastProgressTs);
        lastProgressTs = now;
        // Time-based progress — same asymptotic curve as the worker path.
        if (progressEl) progressEl.style.width = timeProgress() + "%";
      }
    }
  }
})();
