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

  // 3f. Font measurement — render text in multiple fonts, hash bounding rects.
  // Different OS/GPU/font configs produce different metrics. Headless Chrome
  // with --no-sandbox has different font rasterization than desktop Chrome.
  signals.fontHash = (() => {
    try {
      const el = document.createElement("span");
      el.style.cssText = "position:absolute;visibility:hidden;font-size:72px";
      el.textContent = "mmmmmmmmmmlli";
      document.body.appendChild(el);
      const fonts = ["monospace", "serif", "sans-serif", "Arial", "Courier New"];
      let hash = 0;
      for (const f of fonts) {
        el.style.fontFamily = f;
        const r = el.getBoundingClientRect();
        hash = ((hash << 5) - hash + Math.round(r.width * 100) + Math.round(r.height * 100)) | 0;
      }
      document.body.removeChild(el);
      return hash;
    } catch { return 0; }
  })();

  // 3g. Canvas fingerprint — draw text + shapes, hash pixel data.
  // GPU/driver-dependent rendering produces per-platform unique hashes.
  signals.canvasHash = (() => {
    try {
      const c = document.createElement("canvas");
      c.width = 200; c.height = 50;
      const ctx = c.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "14px Arial";
      ctx.fillStyle = "#f60";
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = "#069";
      ctx.fillText("Cwm fjord veg", 2, 15);
      ctx.fillStyle = "rgba(102,204,0,0.7)";
      ctx.fillText("bank glyphs", 4, 35);
      const data = ctx.getImageData(0, 0, 200, 50).data;
      let hash = 0;
      for (let i = 0; i < data.length; i += 4) {
        hash = ((hash << 5) - hash + data[i] + data[i+1] + data[i+2]) | 0;
      }
      return hash;
    } catch { return 0; }
  })();

  // 3h. Storage quota — headless/incognito environments report 0 or restricted quota.
  signals.storageQuota = await (async () => {
    try {
      const est = await navigator.storage.estimate();
      return est.quota || 0;
    } catch { return -1; }
  })();

  // 3i. Media queries — display capabilities hard to fake without real display.
  signals.colorGamut = (() => {
    try {
      if (matchMedia("(color-gamut: p3)").matches) return "p3";
      if (matchMedia("(color-gamut: srgb)").matches) return "srgb";
    } catch {}
    return "none";
  })();
  signals.prefersRM = (() => {
    try { return matchMedia("(prefers-reduced-motion: reduce)").matches ? 1 : 0; }
    catch { return -1; }
  })();
  signals.dynRange = (() => {
    try { return matchMedia("(dynamic-range: high)").matches ? 1 : 0; }
    catch { return -1; }
  })();

  // 3j. Network connection info — real Chrome always has NetworkInformation API.
  signals.connType = (() => {
    try { return navigator.connection ? navigator.connection.effectiveType || "" : ""; }
    catch { return ""; }
  })();

  // ── Layer 4: Behavioral Signals ─────────────────────────────────
  // Collected during PoW computation.
  const behavior = { me: 0, ke: 0, fc: 0, se: 0, fi: -1, has: document.hidden ? 1 : 0 };
  const progressTimings = [];
  let lastProgressTs = Date.now();

  // 4a. Mouse velocity tracking — bots either don't move or move at constant velocity.
  let lastMX = 0, lastMY = 0, lastMT = 0;
  const velocities = [];
  // 4b. Mouse direction tracking — for movement entropy calculation.
  const directions = [];

  const onMouse = (e) => {
    behavior.me++;
    if (behavior.fi < 0) behavior.fi = Date.now() - t0;
    // Track velocity
    const now = Date.now();
    if (lastMT > 0) {
      const dt = now - lastMT;
      if (dt > 0 && dt < 500) {
        const dx = e.clientX - lastMX;
        const dy = e.clientY - lastMY;
        const dist = Math.sqrt(dx * dx + dy * dy);
        velocities.push(dist / dt);
        // Quantize direction to 8 compass points for entropy
        const angle = Math.atan2(dy, dx);
        directions.push(Math.round((angle + Math.PI) / (Math.PI / 4)) % 8);
      }
    }
    lastMX = e.clientX; lastMY = e.clientY; lastMT = now;
  };
  const onKey = () => { behavior.ke++; if (behavior.fi < 0) behavior.fi = Date.now() - t0; };
  const onFocus = () => behavior.fc++;
  const onScroll = () => { behavior.se++; if (behavior.fi < 0) behavior.fi = Date.now() - t0; };

  // 4e. Fake touch detection — touchstart on non-touch device.
  let fakeTouch = 0;
  const onTouch = () => { if (navigator.maxTouchPoints === 0) fakeTouch = 1; };

  // 4d. requestAnimationFrame timing probe — headless browsers have
  // suspiciously uniform rAF intervals due to no real display vsync.
  const rafTimes = [];
  let rafCount = 0;
  function rafProbe(ts) {
    rafTimes.push(ts);
    if (++rafCount < 30) requestAnimationFrame(rafProbe);
  }
  requestAnimationFrame(rafProbe);

  document.addEventListener("mousemove", onMouse);
  document.addEventListener("keydown", onKey);
  document.addEventListener("visibilitychange", onFocus);
  document.addEventListener("scroll", onScroll);
  document.addEventListener("touchstart", onTouch, { once: true });

  // ── Submit solution to verify endpoint ──────────────────────────
  const submitSolution = async (hash, nonce) => {
    // Remove listeners
    document.removeEventListener("mousemove", onMouse);
    document.removeEventListener("keydown", onKey);
    document.removeEventListener("visibilitychange", onFocus);
    document.removeEventListener("scroll", onScroll);
    document.removeEventListener("touchstart", onTouch);

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

    // Compute mouse velocity histogram (3 buckets: slow/medium/fast).
    let mvs = 0, mvm = 0, mvf = 0;
    for (const v of velocities) {
      if (v < 0.5) mvs++;
      else if (v <= 2.0) mvm++;
      else mvf++;
    }

    // Compute mouse movement entropy (Shannon entropy of 8 compass directions).
    let ment = 0;
    if (directions.length >= 10) {
      const counts = new Array(8).fill(0);
      for (const d of directions) counts[d]++;
      const total = directions.length;
      for (const c of counts) {
        if (c > 0) {
          const p = c / total;
          ment -= p * Math.log2(p);
        }
      }
      ment = Math.round(ment * 100) / 100;
    } else {
      ment = -1; // insufficient data
    }

    // Compute rAF timing variance — headless has suspiciously uniform intervals.
    let rafv = -1;
    if (rafTimes.length >= 10) {
      const intervals = [];
      for (let i = 1; i < rafTimes.length; i++) intervals.push(rafTimes[i] - rafTimes[i - 1]);
      const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const variance = intervals.reduce((a, b) => a + (b - mean) ** 2, 0) / intervals.length;
      rafv = Math.round(Math.sqrt(variance) * 100) / 100;
    }

    // Signals — XOR-encrypted with per-request key to prevent casual inspection.
    // Falls back to plaintext if signal_key is not present (shouldn't happen).
    const sigJSON = JSON.stringify(signals);
    const behJSON = JSON.stringify({
      ...behavior,
      wtv: wtv,
      dur: Date.now() - t0,
      mvs: mvs,
      mvm: mvm,
      mvf: mvf,
      ment: ment,
      rafv: rafv,
      ft: fakeTouch,
    });
    if (config.signal_key) {
      const xorEnc = (str, key) => {
        const enc = new Uint8Array(str.length);
        for (let i = 0; i < str.length; i++) {
          enc[i] = str.charCodeAt(i) ^ key.charCodeAt(i % key.length);
        }
        return btoa(String.fromCharCode(...enc));
      };
      form.set("signals_enc", xorEnc(sigJSON, config.signal_key));
      form.set("behavior_enc", xorEnc(behJSON, config.signal_key));
    } else {
      form.set("signals", sigJSON);
      form.set("behavior", behJSON);
    }

    // POST without redirect:"manual" — the verify endpoint returns 200 JSON
    // with {redirect: url}. This ensures the browser processes the Set-Cookie
    // header (opaque redirect responses from redirect:"manual" suppress cookies).
    const resp = await fetch("/.well-known/policy-challenge/verify", {
      method: "POST",
      body: form,
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

    if (resp.ok) {
      try {
        const data = await resp.json();
        window.location.replace(data.redirect || original_url || "/");
      } catch {
        window.location.replace(original_url || "/");
      }
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
