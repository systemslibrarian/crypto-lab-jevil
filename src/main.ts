// src/main.ts — Jevil demo UI.
//
// All cryptography runs in-browser over the real Goldilocks field. The cliff,
// the recovery, and the "EXACT MATCH" verdict are computed live from public
// ledger data via Lagrange interpolation — nothing here is pre-baked.

import "./style.css";
import { fmt, fmtFull, mod } from "./field";
import {
  keyGen,
  sign,
  Ledger,
  checkCliff,
  findDisjointMessage,
  type JevilKey,
  type CliffStatus,
} from "./jevil";
import { renderPlot } from "./plot";
import { renderCompare } from "./compare";

// ---------------------------------------------------------------- state ----
let key: JevilKey | null = null;
let ledger: Ledger | null = null;
let grindNonce = 0;

const $ = <T extends HTMLElement = HTMLElement>(sel: string) =>
  document.querySelector(sel) as T;

function randomSeed(): string {
  const buf = new Uint8Array(8);
  crypto.getRandomValues(buf);
  return Array.from(buf)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function seedToNum(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

// ----------------------------------------------------------- rendering ----
function shell(): string {
  return `
  <a class="skip-link" href="#main-content">Skip to content</a>
  <header class="hero">
    <button id="theme-toggle" class="theme-toggle" aria-label="Switch to light mode" style="position: absolute; top: 0; right: 0"><span aria-hidden="true">🌙</span></button>
    <div class="hero-top">
      <span class="kicker">Crypto-Lab</span>
    </div>
    <h1 class="title">Jevil</h1>
    <p class="subtitle">A catastrophic-failure-by-design signature scheme</p>
    <p class="lede">
      Most few-time signatures fail <em>softly</em>: sign once too often and the
      forgery probability creeps up like a gentle slope. Jevil fails the opposite
      way — a sharp <strong class="danger-text">cliff</strong>. Stay within budget
      and the key is ~124-bit safe. Cross it by a single signature and the secret
      key doesn't leak gradually — it falls out <em>whole</em>, reconstructable by
      anyone from the public record.
    </p>
    <p class="attribution">
      Mechanic from Kobeissi,
      <a href="https://eprint.iacr.org/2026/1103" target="_blank" rel="noopener">
      &ldquo;Jevil&rdquo;, Cryptology ePrint 2026/1103</a>. The cliff here is
      <strong>real Lagrange interpolation over the Goldilocks field</strong>,
      computed live in your browser — not a simulation, not a scripted reveal.
    </p>
  </header>

  <main class="panels" id="main-content" tabindex="-1">

    <section class="panel" id="panel-key">
      <div class="panel-head"><span class="panel-num" aria-hidden="true">01</span><h2>Generate a key</h2></div>
      <p class="panel-intro">
        The secret key is the coefficient vector of a random degree-<code>D</code>
        polynomial <code>f</code>. <strong>The coefficients are the secret.</strong>
        The budget <code>n*</code> fixes how many times it is safe to sign.
      </p>
      <div class="controls">
        <label>Budget <code>n*</code>
          <select id="sel-nstar">
            <option value="1">1</option>
            <option value="2">2</option>
            <option value="3" selected>3</option>
            <option value="4">4</option>
            <option value="5">5</option>
            <option value="6">6</option>
            <option value="7">7</option>
          </select>
        </label>
        <label>Positions / sig <code>K</code>
          <select id="sel-k">
            <option value="2">2 — Figure 1 of the paper</option>
            <option value="3" selected>3</option>
            <option value="4">4</option>
          </select>
        </label>
        <button id="btn-gen" class="btn btn-primary">Generate key</button>
      </div>
      <p class="note">
        &#9432; <strong>Small params for visual clarity.</strong> Like RSA Forge's
        small/large-key toggle, tiny <code>n*</code> and <code>K</code> keep the
        point count legible. Real Jevil uses <code>K=16+</code> for ~124-bit
        security; the cliff geometry is identical at any size.
      </p>
      <div id="key-out" class="key-out hidden"></div>
    </section>

    <section class="panel" id="panel-sign">
      <div class="panel-head"><span class="panel-num" aria-hidden="true">02</span><h2>Sign messages</h2></div>
      <p class="panel-intro">
        Each signature reveals <code>K</code> evaluations of <code>f</code> at
        hash-derived positions. Honest signing takes whatever the message hashes
        to. The <span class="danger-text">grind</span> is the worst case: an
        adversary picking messages whose positions are all <em>fresh</em>, packing
        the ledger as fast as possible.
      </p>
      <div class="controls">
        <label class="ctrl-msg">Message to sign
          <input id="msg" type="text" placeholder="a message to sign…" value="release v1.0" autocomplete="off" />
        </label>
        <button id="btn-sign" class="btn">Sign (honest)</button>
        <button id="btn-grind" class="btn btn-danger">Grind toward cliff &#9889;</button>
      </div>
      <p id="sign-hint" class="hint" role="status" aria-live="polite"></p>
    </section>

    <section class="panel" id="panel-cliff">
      <div class="panel-head"><span class="panel-num" aria-hidden="true">03</span><h2>The cliff</h2></div>
      <div class="meter-wrap">
        <div class="meter-labels">
          <span id="meter-label">distinct points</span>
          <span id="meter-count">&mdash; / &mdash;</span>
        </div>
        <div class="meter" id="meter" role="progressbar" aria-labelledby="meter-label"
          aria-valuemin="0" aria-valuenow="0" aria-valuetext="no key generated yet">
          <div id="meter-fill" class="meter-fill"></div>
        </div>
      </div>
      <div id="cliff-status" class="cliff-status" role="status" aria-live="polite">Generate a key to begin.</div>
      <figure class="plot-figure">
        <div id="plot" class="plot"></div>
        <figcaption class="plot-caption">
          Gold hollow dot = the out-of-domain freebie baked into the public key.
          Red dots = points revealed by signatures. Below the cliff, several
          degree-<code>D</code> curves fit the same points — the secret is one of
          infinitely many. At <code>D+1</code> points they collapse to one.
        </figcaption>
      </figure>
    </section>

    <section class="panel danger-panel hidden" id="panel-recover">
      <div class="panel-head"><span class="panel-num" aria-hidden="true">04</span><h2>Secret recovered</h2></div>
      <p class="panel-intro">
        The key the signer believed was private, reconstructed from public data
        alone. Recovered coefficients (left) vs. the true secret (right),
        compared row by row — live, in your browser.
      </p>
      <div id="recover-out"></div>
    </section>

    <section class="panel" id="panel-ledger">
      <div class="panel-head"><span class="panel-num" aria-hidden="true">05</span><h2>Public ledger</h2></div>
      <p class="panel-intro">
        Everything an observer sees. The OOD freebie is gold-bordered. Duplicate
        positions (same <code>x</code>) are struck through — they do not advance
        the cliff.
      </p>
      <div id="ledger-out" class="ledger-out"><p class="muted">No signatures yet.</p></div>
    </section>

    <section class="panel" id="panel-compare">
      <div class="panel-head"><span class="panel-num" aria-hidden="true">06</span><h2>Soft slope vs sharp cliff</h2></div>
      <p class="panel-intro">
        Why the cliff matters, in one picture — at <em>your</em> chosen
        <code>n*</code> and <code>K</code>. A HORS-family scheme (FORS in SLH-DSA)
        leaks security <em>gradually</em>: forgery probability climbs as
        <code>(rK/T)<sup>K</sup></code> with every signature <code>r</code>. Jevil
        stays negligible through the budget, then falls off a vertical cliff at
        signature <code>n*+1</code>.
      </p>
      <figure class="cmp-figure">
        <div id="compare" class="compare"></div>
        <figcaption class="cmp-legend">
          <span class="cmp-key cmp-key-soft">soft FTS — gradual slope</span>
          <span class="cmp-key cmp-key-jevil">Jevil — flat, then cliff</span>
          <span class="cmp-note">Real FORS uses a far larger <code>T</code>, so its slope stays low much longer; the small demo <code>T</code> just makes the shape legible.</span>
        </figcaption>
      </figure>
    </section>

    <section class="prose">
      <h2>Why this matters</h2>
      <p>
        Stateful hash-based signatures (XMSS, LMS) are also few-time-ish: each
        one-time key must be used <em>once</em>. But they fail <strong>silently</strong>.
        Restore a machine from a backup, the signature counter rolls back, and the
        same one-time key material signs two different messages — with no outward
        sign that anything went wrong. The forgery risk is created quietly and
        carried by everyone who trusts the key.
      </p>
      <p>
        Jevil relocates the consequence <strong>into the cryptographic object</strong>.
        Oversigning doesn't fail quietly and against the verifier — it fails
        <strong class="danger-text">loudly and against the signer</strong>. The
        moment the budget is exceeded, the private key becomes computable by
        anyone watching, an event detectable by everyone. The penalty lands on the
        party that broke the rule.
      </p>
      <p>That trade is useful wherever a hard signing cap is the security property:</p>
      <ul>
        <li><strong>Firmware vendors</strong> capping the number of signed releases per key.</li>
        <li><strong>Per-tenure attestation budgets</strong> — an authority that may attest only <code>n*</code> times.</li>
        <li><strong>Ephemeral session signers</strong> with a built-in, self-enforcing expiry.</li>
        <li><strong>Audit-budgeted credentials</strong> where exceeding the budget must be undeniable.</li>
      </ul>
      <p class="claim">
        Per the paper's Table 1, Jevil is the first <strong>post-quantum,
        transparent, sharp-cliff, count-triggered</strong> few-time signature
        scheme — combining properties no prior FTS offered together.
      </p>
    </section>

    <section class="prose callout-real">
      <h2>What's real, what's illustrative</h2>
      <p>
        The cliff is faithful: real finite-field arithmetic, hash-derived
        positions, an accumulating distinct-point ledger, and genuine
        <code>O(D&sup2;)</code> Lagrange recovery that is verified to reproduce the
        true secret exactly. The plot is a real-number <em>geometric</em>
        illustration, and the load-bearing zk-WHIR commitment layer is
        <strong>not</strong> implemented — so this demo shows the cliff geometry,
        not the commitment that makes it binding on a malicious signer.
        Full honesty in <a href="https://github.com/systemslibrarian/crypto-lab-jevil/blob/main/KNOWN-GAPS.md" target="_blank" rel="noopener"><code>KNOWN-GAPS.md</code></a>.
      </p>
    </section>

    <section class="prose related">
      <h2>Related Crypto-Lab demos</h2>
      <nav class="related-grid" aria-label="Related Crypto-Lab demos">
        <a class="related-card" href="https://systemslibrarian.github.io/crypto-lab-rsa-forge/" target="_blank" rel="noopener">
          <strong>RSA Forge</strong><span>Textbook RSA, OAEP, PSS, and forgery attacks.</span></a>
        <a class="related-card" href="https://systemslibrarian.github.io/crypto-lab-dilithium-seal/" target="_blank" rel="noopener">
          <strong>Dilithium Seal</strong><span>ML-DSA lattice signatures, end to end.</span></a>
        <a class="related-card" href="https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/" target="_blank" rel="noopener">
          <strong>SPHINCS Ledger</strong><span>SLH-DSA / FORS &mdash; the <em>soft</em>-degradation counterpoint.</span></a>
        <a class="related-card" href="https://systemslibrarian.github.io/crypto-lab-kyber-vault/" target="_blank" rel="noopener">
          <strong>Kyber Vault</strong><span>ML-KEM key encapsulation, visualized.</span></a>
        <a class="related-card" href="https://systemslibrarian.github.io/" target="_blank" rel="noopener">
          <strong>Crypto-Lab</strong><span>The full suite of interactive demos.</span></a>
      </nav>
    </section>

    <footer class="scripture-footer">
      <a href="https://github.com/systemslibrarian/crypto-lab-jevil" target="_blank" rel="noopener">
        github.com/systemslibrarian/crypto-lab-jevil</a>
      <p>So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31</p>
    </footer>
  </main>`;
}

// ------------------------------------------------------------- handlers ----
async function doGenerate() {
  const nStar = parseInt($<HTMLSelectElement>("#sel-nstar").value, 10);
  const K = parseInt($<HTMLSelectElement>("#sel-k").value, 10);
  const seed = randomSeed();
  key = await keyGen(nStar, K, seed);
  ledger = new Ledger(key);
  grindNonce = 0;

  const p = key.params;
  $("#key-out").classList.remove("hidden");
  $("#key-out").innerHTML = `
    <div class="kv-grid">
      <div class="kv"><span>budget n*</span><code>${p.nStar}</code></div>
      <div class="kv"><span>positions K</span><code>${p.K}</code></div>
      <div class="kv"><span>coefficients M = (n*+1)&middot;K</span><code>${p.M}</code></div>
      <div class="kv"><span>degree D = M&minus;1</span><code>${p.D}</code></div>
      <div class="kv"><span>domain T</span><code>${p.T}</code></div>
      <div class="kv danger-kv"><span>cliff fires at signature</span><code>n*+1 = ${p.nCliff}</code></div>
    </div>
    <p class="ood-line">
      Public out-of-domain freebie&nbsp; <span class="ood-pair">(z=${fmt(key.ood.x)}, f(z)=${fmt(key.ood.y)})</span>
      &mdash; one free point on <code>f</code>, baked into the public key.
    </p>
    <p class="secret-line">
      Secret: a degree-${p.D} polynomial &mdash; ${p.M} hidden coefficients over the
      Goldilocks field <code>q&#8320; = 2&#8310;&#8308; &minus; 2&#179;&#178; + 1</code>.
    </p>`;

  $("#sign-hint").textContent = "";
  $("#recover-out").innerHTML = "";
  $("#panel-recover").classList.add("hidden");
  // Soft-vs-sharp comparison depends only on the chosen params.
  $("#compare").innerHTML = renderCompare(key.params);
  update();
}

async function doSignHonest() {
  if (!key || !ledger) return flash("Generate a key first.");
  const msg = $<HTMLInputElement>("#msg").value.trim() || "(empty)";
  const before = checkCliff(key, ledger).distinct;
  const sig = await sign(key, msg, ledger.signatures.length + 1, ledger.usedX());
  ledger.add(sig);
  const after = checkCliff(key, ledger);
  reportSign(sig.fresh, before, after, `Honest sign of &ldquo;${escapeHtml(msg)}&rdquo;`);
  update();
}

async function doGrind() {
  if (!key || !ledger) return flash("Generate a key first.");
  if (checkCliff(key, ledger).reached) return flash("Cliff already reached &mdash; the secret is already public.");
  const before = checkCliff(key, ledger).distinct;
  const dr = await findDisjointMessage(key, ledger.usedX(), grindNonce);
  grindNonce = grindNonce + dr.noncesTried + 1;
  const sig = await sign(key, dr.message, ledger.signatures.length + 1, ledger.usedX());
  ledger.add(sig);
  const after = checkCliff(key, ledger);
  reportSign(
    sig.fresh,
    before,
    after,
    `&#9889; Grind picked &ldquo;${escapeHtml(dr.message)}&rdquo; (${dr.noncesTried} tries) &mdash; all ${sig.fresh} positions fresh`,
  );
  update();
}

function reportSign(fresh: number, before: number, after: CliffStatus, label: string) {
  const remaining = Math.max(0, after.needed - after.distinct);
  const tail = after.reached
    ? `&mdash; <strong class="danger-text">cliff reached: ${after.distinct} &ge; ${after.needed}.</strong>`
    : `${remaining} more distinct point${remaining === 1 ? "" : "s"} to the cliff.`;
  $("#sign-hint").innerHTML =
    `${label}: +${fresh} distinct (${before} &rarr; ${after.distinct}). ${tail}`;
}

function flash(msg: string) {
  $("#sign-hint").innerHTML = `<span class="danger-text">${msg}</span>`;
}

// --------------------------------------------------------- live update ----
function update() {
  if (!key || !ledger) return;
  const cliff = checkCliff(key, ledger);

  // Meter (also exposed as an ARIA progressbar).
  const pct = Math.min(100, (cliff.distinct / cliff.needed) * 100);
  const fill = $("#meter-fill");
  fill.style.width = pct.toFixed(1) + "%";
  fill.className = "meter-fill " + meterClass(pct, cliff.reached);
  $("#meter-count").textContent = `${cliff.distinct} / ${cliff.needed}`;
  const meter = $("#meter");
  meter.setAttribute("aria-valuemax", String(cliff.needed));
  meter.setAttribute("aria-valuenow", String(cliff.distinct));
  meter.setAttribute(
    "aria-valuetext",
    `${cliff.distinct} of ${cliff.needed} distinct points` +
      (cliff.reached ? " — cliff reached, secret recovered" : ""),
  );

  // Disable the grind once the cliff has fired (the secret is already public).
  const grind = $<HTMLButtonElement>("#btn-grind");
  grind.disabled = cliff.reached;
  grind.setAttribute("aria-disabled", String(cliff.reached));

  // Status callout.
  const status = $("#cliff-status");
  if (cliff.reached) {
    status.className = "cliff-status danger shake";
    status.innerHTML =
      `&#9888; <strong>Secret recovered.</strong> ${cliff.distinct} distinct points &ge; D+1 = ${cliff.needed}. ` +
      `The polynomial is uniquely determined and reconstructed below.`;
  } else {
    status.className = "cliff-status safe";
    const left = cliff.needed - cliff.distinct;
    status.innerHTML =
      `&#128274; <strong>Secret undetermined.</strong> ${cliff.distinct} of ${cliff.needed} ` +
      `points &mdash; ${left} short. Infinitely many degree-${key.params.D} polynomials still fit.`;
  }

  // Plot.
  $("#plot").innerHTML = renderPlot({
    D: key.params.D,
    revealed: cliff.distinct,
    cliffReached: cliff.reached,
    seedNum: seedToNum(key.rootHint),
  });

  renderRecovery(cliff);
  renderLedger();
}

function meterClass(pct: number, reached: boolean): string {
  if (reached) return "danger";
  if (pct >= 66) return "warn";
  return "safe";
}

function renderRecovery(cliff: CliffStatus) {
  const panel = $("#panel-recover");
  if (!cliff.reached || !cliff.recovered || !key) {
    panel.classList.add("hidden");
    return;
  }
  panel.classList.remove("hidden");
  const recovered = cliff.recovered;
  const rows = key.coeffs
    .map((trueC, i) => {
      const rec = recovered[i];
      const match = mod(rec) === mod(trueC);
      return `<tr class="${match ? "match" : "mismatch"}">
        <th scope="row" class="idx">c<sub>${i}</sub></th>
        <td class="mono">${fmtFull(rec)}</td>
        <td class="cmp" aria-label="${match ? "matches" : "differs"}"><span aria-hidden="true">${match ? "&#10003;" : "&#10007;"}</span></td>
        <td class="mono">${fmtFull(trueC)}</td>
      </tr>`;
    })
    .join("");
  const verdict = cliff.exact
    ? `<div class="verdict exact" role="status">EXACT MATCH &mdash; all ${key.coeffs.length} coefficients reconstructed from public data.</div>`
    : `<div class="verdict bad" role="status">MISMATCH &mdash; recovery did not reproduce the secret.</div>`;
  $("#recover-out").innerHTML = `
    ${verdict}
    <div class="table-scroll" tabindex="0" role="region" aria-label="Recovered coefficients versus true secret (scrollable)">
      <table class="coeff-table">
        <caption class="sr-only">Each row compares a recovered coefficient with the true secret coefficient.</caption>
        <thead><tr><th scope="col">coeff</th><th scope="col">recovered (from public data)</th><th scope="col"><span class="sr-only">match</span></th><th scope="col">true secret</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

function renderLedger() {
  if (!ledger || !key) return;
  const seen = new Set<string>();
  const out: string[] = [];

  // OOD freebie.
  seen.add(key.ood.x.toString());
  out.push(`
    <div class="led-group ood-group">
      <div class="led-tag">OOD freebie &middot; baked into public key</div>
      <div class="led-points">
        <span class="led-pt ood-pt">x=${fmt(key.ood.x)} &middot; f(x)=${fmt(key.ood.y)}</span>
      </div>
    </div>`);

  ledger.signatures.forEach((s) => {
    const pts = s.points
      .map((p) => {
        const k = p.x.toString();
        const dup = seen.has(k);
        if (!dup) seen.add(k);
        return `<span class="led-pt ${dup ? "dup" : ""}" title="position index i=${p.index}">
          x=${fmt(p.x)} &middot; f(x)=${fmt(p.y)}${dup ? " &middot;dup" : ""}</span>`;
      })
      .join("");
    out.push(`
      <div class="led-group">
        <div class="led-tag">signature #${s.signatureNumber} &middot; &ldquo;${escapeHtml(s.message)}&rdquo; &middot; +${s.fresh} distinct</div>
        <div class="led-points">${pts}</div>
      </div>`);
  });

  $("#ledger-out").innerHTML = out.join("");
}

function escapeHtml(s: string): string {
  return s.replace(
    /[&<>"]/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!,
  );
}

// ----------------------------------------------------------------- boot ----
function boot() {
  $("#app").innerHTML = shell();
  $("#btn-gen").addEventListener("click", () => void doGenerate());
  $("#btn-sign").addEventListener("click", () => void doSignHonest());
  $("#btn-grind").addEventListener("click", () => void doGrind());
  // Press Enter in the message field to sign honestly.
  $("#msg").addEventListener("keydown", (e) => {
    if ((e as KeyboardEvent).key === "Enter") {
      e.preventDefault();
      void doSignHonest();
    }
  });

  // Theme toggle: flip data-theme on <html>, persist, and keep the button's
  // emoji + aria-label in sync with the active theme. Dark is the default
  // (set by the anti-flash script in index.html).
  const html = document.documentElement;
  const syncThemeButton = (theme: string) => {
    const btn = $("#theme-toggle");
    const dark = theme === "dark";
    btn.innerHTML = `<span aria-hidden="true">${dark ? "🌙" : "☀️"}</span>`;
    btn.setAttribute(
      "aria-label",
      dark ? "Switch to light mode" : "Switch to dark mode",
    );
  };
  syncThemeButton(html.getAttribute("data-theme") ?? "dark");
  $("#theme-toggle").addEventListener("click", () => {
    const next = html.getAttribute("data-theme") === "dark" ? "light" : "dark";
    html.setAttribute("data-theme", next);
    localStorage.setItem("theme", next);
    syncThemeButton(next);
  });

  void doGenerate();
}

boot();
