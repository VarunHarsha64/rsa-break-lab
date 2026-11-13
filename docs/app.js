/* app.js
 * Loads the REAL rsa_break_lab Python source (same files as the repo's
 * src/) into Pyodide and runs the attacks for real, in the browser.
 * Nothing here is faked or pre-recorded.
 */

let pyodideReady = null;

function setStatus(state, text) {
  const dot = document.getElementById("pyodide-dot");
  const label = document.getElementById("pyodide-label");
  dot.className = "dot " + state;
  label.textContent = text;
}

async function loadPythonPackage(pyodide) {
  const manifest = await (await fetch("pyruntime_manifest.json")).json();
  for (const relPath of manifest) {
    const text = await (await fetch("pyruntime/" + relPath)).text();
    const fullPath = "/pylib/" + relPath;
    const dir = fullPath.substring(0, fullPath.lastIndexOf("/"));
    pyodide.FS.mkdirTree(dir);
    pyodide.FS.writeFile(fullPath, text);
  }
}

function logLine(containerId, text, cls) {
  const el = document.getElementById(containerId);
  const line = document.createElement("div");
  line.className = "line" + (cls ? " " + cls : "");
  line.textContent = text;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
}

async function initPyodide() {
  setStatus("loading", "Loading Pyodide + rsa_break_lab\u2026");
  try {
    const pyodide = await loadPyodide();
    await loadPythonPackage(pyodide);
    await pyodide.runPythonAsync(
      'import sys\nif "/pylib" not in sys.path:\n    sys.path.insert(0, "/pylib")\nfrom rsa_break_lab import rsa_core\n'
    );
    setStatus("ready", "Ready \u2014 running real Python, in your browser, via WebAssembly");
    document.querySelectorAll("button.run").forEach((b) => (b.disabled = false));
    return pyodide;
  } catch (err) {
    console.error(err);
    setStatus("error", "Failed to load Pyodide: " + err.message);
    throw err;
  }
}

function getPyodide() {
  if (!pyodideReady) pyodideReady = initPyodide();
  return pyodideReady;
}

function showBanner(id, ok, text) {
  const el = document.getElementById(id);
  el.className = "result-banner show " + (ok ? "ok" : "fail");
  el.textContent = text;
}

async function runCode(consoleId, code) {
  const pyodide = await getPyodide();
  pyodide.globals.set("js_log_line", (text, cls) => logLine(consoleId, text, cls));
  const jsonResult = await pyodide.runPythonAsync(code);
  return JSON.parse(jsonResult);
}

function clearConsole(id) {
  document.getElementById(id).innerHTML = "";
}

function setButtonsDisabled(disabled, ...ids) {
  ids.forEach((id) => (document.getElementById(id).disabled = disabled));
}

/* ---------------------------------------------------------------- */
/* Attack 1: Fermat factorization                                    */
/* ---------------------------------------------------------------- */

async function runFermat() {
  const gapBits = parseInt(document.getElementById("fermat-gap").value, 10);
  const bits = 256;
  clearConsole("fermat-console");
  setButtonsDisabled(true, "fermat-run");
  const code = `
import json, time
from rsa_break_lab import rsa_core
from rsa_break_lab.attacks.fermat import fermat_factor

js_log_line(f"Generating a ${bits}-bit RSA modulus with p, q only ~${gapBits} bits apart...", "dim")
kp = rsa_core.generate_close_primes_keypair(bits=${bits}, gap_bits=${gapBits})
js_log_line("n = " + str(kp.n), "dim")
js_log_line("Running Fermat's factorization method...", "hl")
t0 = time.perf_counter()
factors, iterations = fermat_factor(kp.n, max_iterations=3_000_000)
dt = (time.perf_counter() - t0) * 1000
if factors:
    p, q = factors
    js_log_line(f"FACTORED in {iterations} iteration(s), {dt:.2f} ms", "ok")
    js_log_line("p = " + str(p), "ok")
    js_log_line("q = " + str(q), "ok")
    result = {"success": True, "iterations": iterations, "duration_ms": dt, "p": str(p), "q": str(q)}
else:
    js_log_line(f"Gave up after {iterations} iterations -- primes too far apart.", "fail")
    result = {"success": False, "iterations": iterations, "duration_ms": dt}
json.dumps(result)
`;
  try {
    const r = await runCode("fermat-console", code);
    showBanner(
      "fermat-banner", r.success,
      r.success ? `Broken in ${r.iterations} iteration(s) / ${r.duration_ms.toFixed(2)} ms.` :
                   `Not broken within the iteration cap -- gap too large for this demo.`
    );
  } finally {
    setButtonsDisabled(false, "fermat-run");
  }
}

/* ---------------------------------------------------------------- */
/* Attack 2: Wiener                                                  */
/* ---------------------------------------------------------------- */

async function runWiener() {
  const dBits = parseInt(document.getElementById("wiener-dbits").value, 10);
  clearConsole("wiener-console");
  setButtonsDisabled(true, "wiener-run");
  const code = `
import json, time
from rsa_break_lab import rsa_core
from rsa_break_lab.attacks.wiener import wiener_attack

bits = 512
js_log_line(f"Generating a {bits}-bit RSA key with a deliberately small d (~${dBits} bits)...", "dim")
kp = rsa_core.generate_small_d_keypair(bits=bits, d_bits=${dBits})
js_log_line("Running Wiener's continued-fraction attack on (e, n)...", "hl")
t0 = time.perf_counter()
d, factors, tried = wiener_attack(kp.e, kp.n)
dt = (time.perf_counter() - t0) * 1000
if d == kp.d:
    js_log_line(f"RECOVERED d after checking {tried} convergent(s), {dt:.2f} ms", "ok")
    js_log_line("d = " + str(d), "ok")
    result = {"success": True, "convergents": tried, "duration_ms": dt}
else:
    js_log_line(f"Failed after {tried} convergent(s) -- d is outside Wiener's vulnerable range.", "fail")
    result = {"success": False, "convergents": tried, "duration_ms": dt}
json.dumps(result)
`;
  try {
    const r = await runCode("wiener-console", code);
    showBanner(
      "wiener-banner", r.success,
      r.success ? `Private key recovered after ${r.convergents} convergent(s) / ${r.duration_ms.toFixed(2)} ms.` :
                   `d was too large for Wiener's attack to work (as expected above the theoretical bound).`
    );
  } finally {
    setButtonsDisabled(false, "wiener-run");
  }
}

/* ---------------------------------------------------------------- */
/* Attack 3: Hastad broadcast                                        */
/* ---------------------------------------------------------------- */

async function runHastad() {
  const k = parseInt(document.getElementById("hastad-k").value, 10);
  clearConsole("hastad-console");
  setButtonsDisabled(true, "hastad-run");
  const code = `
import json, time, random
from rsa_break_lab import rsa_core
from rsa_break_lab.attacks.hastad import hastad_broadcast

k = ${k}
e = 3
bits = 256
# Message close in size to the modulus so m**e genuinely wraps mod n_i --
# otherwise a single ciphertext's plain e-th root would already reveal it.
message = random.getrandbits(bits - 16) | (1 << (bits - 17))
js_log_line(f"Broadcasting the SAME {bits - 16}-bit message to {k} recipient(s), each with their own {bits}-bit modulus, all using e={e}...", "dim")
keypairs, cts = rsa_core.generate_broadcast_instance(message=message, k=k, bits=bits, e=e)
pairs = list(zip([kp.n for kp in keypairs], cts))
for i, (n, c) in enumerate(pairs):
    js_log_line(f"  ciphertext {i}: n=...{str(n)[-12:]}  c=...{str(c)[-12:]}", "dim")
attack_pairs = pairs[:e] if len(pairs) >= e else pairs
js_log_line("Combining via CRT and taking an integer e-th root...", "hl")
t0 = time.perf_counter()
recovered, details = hastad_broadcast(attack_pairs)
dt = (time.perf_counter() - t0) * 1000
if recovered == message:
    js_log_line(f"RECOVERED message = {recovered} (matches the real plaintext!), {dt:.2f} ms", "ok")
    result = {"success": True, "message": recovered, "duration_ms": dt}
else:
    js_log_line(f"Could not take an exact root -- need at least e={e} ciphertexts.", "fail")
    result = {"success": False, "duration_ms": dt}
json.dumps(result)
`;
  try {
    const r = await runCode("hastad-console", code);
    showBanner(
      "hastad-banner", r.success,
      r.success ? `Message recovered with zero private keys, zero factoring. (${r.duration_ms.toFixed(2)} ms)` :
                   `Need at least 3 intercepted ciphertexts (e = 3) for this to work.`
    );
  } finally {
    setButtonsDisabled(false, "hastad-run");
  }
}

/* ---------------------------------------------------------------- */
/* Attack 4: Common modulus                                          */
/* ---------------------------------------------------------------- */

async function runCommonModulus() {
  const bits = parseInt(document.getElementById("cm-bits").value, 10);
  clearConsole("cm-console");
  setButtonsDisabled(true, "cm-run");
  const code = `
import json, time
from rsa_break_lab import rsa_core
from rsa_break_lab.attacks.common_modulus import common_modulus_attack

bits = ${bits}
message = 20261113
js_log_line(f"Two 'users' share one {bits}-bit modulus n but use different exponents e1, e2...", "dim")
n, (e1, c1), (e2, c2) = rsa_core.generate_common_modulus_instance(message=message, bits=bits)
js_log_line(f"e1={e1}   e2={e2}", "dim")
js_log_line("Solving Bezout's identity a*e1 + b*e2 = 1 and combining ciphertexts...", "hl")
t0 = time.perf_counter()
m = common_modulus_attack(n, e1, c1, e2, c2)
dt = (time.perf_counter() - t0) * 1000
if m == message:
    js_log_line(f"RECOVERED message = {m}, {dt:.2f} ms -- no private key, no factoring!", "ok")
    result = {"success": True, "message": m, "duration_ms": dt}
else:
    js_log_line("Attack failed.", "fail")
    result = {"success": False, "duration_ms": dt}
json.dumps(result)
`;
  try {
    const r = await runCode("cm-console", code);
    showBanner(
      "cm-banner", r.success,
      r.success ? `Message recovered in ${r.duration_ms.toFixed(2)} ms, straight from the two ciphertexts.` :
                   `Attack failed.`
    );
  } finally {
    setButtonsDisabled(false, "cm-run");
  }
}

/* ---------------------------------------------------------------- */
/* Attack 5: Batch GCD                                                */
/* ---------------------------------------------------------------- */

async function runBatchGcd() {
  const poolSize = parseInt(document.getElementById("bgcd-pool").value, 10);
  clearConsole("bgcd-console");
  setButtonsDisabled(true, "bgcd-run");
  const code = `
import json, time
from rsa_break_lab import rsa_core
from rsa_break_lab.attacks.batch_gcd import batch_gcd

pool_size = ${poolSize}
bits = 128
js_log_line(f"Generating {pool_size} 'independent' {bits}-bit moduli; secretly, one pair shares a prime factor...", "dim")
pool = rsa_core.generate_shared_prime_pool(count=pool_size, bits=bits, num_colliding_pairs=1)
moduli = [kp.n for kp in pool]
js_log_line("Running pairwise GCD across every pair of moduli...", "hl")
t0 = time.perf_counter()
compromised, comparisons = batch_gcd(moduli)
dt = (time.perf_counter() - t0) * 1000
if compromised:
    idxs = sorted(compromised.keys())
    shared_p, _ = compromised[idxs[0]]
    js_log_line(f"FOUND shared prime between key #{idxs[0]} and key #{idxs[1]} after {comparisons} comparisons, {dt:.2f} ms", "ok")
    js_log_line("shared p = ..." + str(shared_p)[-16:], "ok")
    result = {"success": True, "comparisons": comparisons, "duration_ms": dt}
else:
    js_log_line("No shared primes found.", "fail")
    result = {"success": False, "comparisons": comparisons, "duration_ms": dt}
json.dumps(result)
`;
  try {
    const r = await runCode("bgcd-console", code);
    showBanner(
      "bgcd-banner", r.success,
      r.success ? `Two keys fully broken via ${r.comparisons} GCD computations -- no factoring algorithm needed.` :
                   `No collision found.`
    );
  } finally {
    setButtonsDisabled(false, "bgcd-run");
  }
}

/* ---------------------------------------------------------------- */
/* Tabs + sliders wiring                                              */
/* ---------------------------------------------------------------- */

function wireTabs() {
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
      document.querySelectorAll(".attack-view").forEach((v) => v.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById(tab.dataset.target).classList.add("active");
    });
  });
}

function wireSlider(sliderId, valueId, formatter) {
  const slider = document.getElementById(sliderId);
  const valueEl = document.getElementById(valueId);
  const update = () => (valueEl.textContent = formatter ? formatter(slider.value) : slider.value);
  slider.addEventListener("input", update);
  update();
}

/* ---------------------------------------------------------------- */
/* Benchmark charts                                                   */
/* ---------------------------------------------------------------- */

async function renderCharts() {
  let rows;
  try {
    rows = await (await fetch("data/benchmark_results.json")).json();
  } catch (e) {
    console.warn("Could not load benchmark data:", e);
    return;
  }

  const mean = (arr) => arr.reduce((a, b) => a + b, 0) / arr.length;
  const groupBy = (attack, param, metric, onlySuccess = true) => {
    const subset = rows.filter((r) => r.attack === attack && r.parameter === param && (!onlySuccess || r.success));
    const buckets = {};
    subset.forEach((r) => {
      (buckets[r.value] = buckets[r.value] || []).push(r[metric]);
    });
    const xs = Object.keys(buckets).map(Number).sort((a, b) => a - b);
    return { xs, ys: xs.map((x) => mean(buckets[x])) };
  };

  const textColor = getComputedStyle(document.documentElement).getPropertyValue("--text-dim").trim();
  const gridColor = getComputedStyle(document.documentElement).getPropertyValue("--border").trim();
  Chart.defaults.color = textColor;
  Chart.defaults.borderColor = gridColor;
  Chart.defaults.font.size = 11;

  // Fermat: time vs gap bits (log scale), including capped/failed runs
  const fermat = groupBy("fermat", "gap_bits", "duration_ms", false);
  new Chart(document.getElementById("chart-fermat"), {
    type: "line",
    data: { labels: fermat.xs, datasets: [{ label: "mean time (ms)", data: fermat.ys, borderColor: "#5b5fe8", tension: 0.15 }] },
    options: {
      scales: { y: { type: "logarithmic", title: { display: true, text: "ms (log)" } }, x: { title: { display: true, text: "prime gap (bits)" } } },
      plugins: { legend: { display: false } },
    },
  });

  // Wiener: success % vs d_bits
  const wienerRows = rows.filter((r) => r.attack === "wiener");
  const wBuckets = {};
  wienerRows.forEach((r) => (wBuckets[r.value] = wBuckets[r.value] || []).push(r.success));
  const wXs = Object.keys(wBuckets).map(Number).sort((a, b) => a - b);
  const wYs = wXs.map((x) => (100 * wBuckets[x].filter(Boolean).length) / wBuckets[x].length);
  new Chart(document.getElementById("chart-wiener"), {
    type: "bar",
    data: { labels: wXs, datasets: [{ label: "success rate (%)", data: wYs, backgroundColor: wXs.map((x) => (x <= 254 ? "#5b5fe8" : "#9aa0b4")) }] },
    options: {
      scales: { y: { min: 0, max: 100, title: { display: true, text: "% recovered" } }, x: { title: { display: true, text: "d (bits), n=1024" } } },
      plugins: { legend: { display: false } },
    },
  });

  // Batch GCD: comparisons vs pool size
  const bgcd = groupBy("batch_gcd", "pool_size", "comparisons");
  new Chart(document.getElementById("chart-bgcd"), {
    type: "line",
    data: { labels: bgcd.xs, datasets: [{ label: "pairwise comparisons", data: bgcd.ys, borderColor: "#2bb3a3", tension: 0.15 }] },
    options: {
      scales: { x: { title: { display: true, text: "pool size" } }, y: { title: { display: true, text: "comparisons" } } },
      plugins: { legend: { display: false } },
    },
  });
}

/* ---------------------------------------------------------------- */

window.addEventListener("DOMContentLoaded", () => {
  wireTabs();
  wireSlider("fermat-gap", "fermat-gap-val");
  wireSlider("wiener-dbits", "wiener-dbits-val");
  wireSlider("hastad-k", "hastad-k-val");
  wireSlider("cm-bits", "cm-bits-val");
  wireSlider("bgcd-pool", "bgcd-pool-val");

  document.getElementById("fermat-run").addEventListener("click", runFermat);
  document.getElementById("wiener-run").addEventListener("click", runWiener);
  document.getElementById("hastad-run").addEventListener("click", runHastad);
  document.getElementById("cm-run").addEventListener("click", runCommonModulus);
  document.getElementById("bgcd-run").addEventListener("click", runBatchGcd);

  getPyodide(); // start loading immediately
  renderCharts();
});
