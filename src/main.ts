// src/main.ts — Jevil demo UI.
//
// All cryptography runs in-browser over the real Goldilocks field. The cliff,
// the recovery, and the "EXACT MATCH" verdict are computed live from public
// ledger data via Lagrange interpolation — nothing here is pre-baked.

import "./style.css";
import { GF, GF4, type Field } from "./ff";
import {
  keyGen,
  sign,
  Ledger,
  checkCliff,
  findDisjointMessage,
  exportTranscript,
  verifyTranscript,
  SEED_BYTES,
  type JevilKey,
  type CliffStatus,
} from "./jevil";
import { candidateCount, formatCount } from "./lagrange";
import { renderPlot } from "./plot";
import { renderCompare } from "./compare";

// ---------------------------------------------------------------- state ----
// Field elements are bigint (base) or bigint[4] (tower); the UI is field-
// agnostic and reads ops/formatting off key.field, so `any` is used here.
let key: JevilKey<any> | null = null;
let ledger: Ledger<any> | null = null;
let grindNonce = 0;

// The export panel reports on ONE ledger state — "reconstructed from N public
// points", or "insufficient points: a of b". Sign again and that sentence
// describes a ledger that no longer exists: exporting below the cliff and then
// grinding to it left "Not verified: insufficient points" sitting under
// "Secret recovered — EXACT MATCH". `update()` stamps the live ledger and
// retires the export line the moment the two diverge.
let ledgerStamp = "";
let exportStamp: string | null = null;

// Serialize async handlers. Each sign/grind/generate reads the ledger, awaits a
// hash, then mutates — so two overlapping runs (e.g. a fast double-click) would
// both read the same signature number and `usedX` before either commits,
// producing duplicate signatures and wrong fresh counts. This drops re-entrant
// calls while one is in flight.
let busy = false;
function guard(fn: () => Promise<void>): () => void {
  return () => {
    if (busy) return;
    busy = true;
    void fn().finally(() => {
      busy = false;
    });
  };
}

const $ = <T extends HTMLElement = HTMLElement>(sel: string) =>
  document.querySelector(sel) as T;

function randomSeed(): string {
  const buf = new Uint8Array(SEED_BYTES);
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
  <main class="panels" id="main-content" tabindex="-1">
  <header class="cl-hero">
    <button id="theme-toggle" class="theme-toggle" aria-label="Switch to light mode" style="position: absolute; top: 0; right: 0"><span aria-hidden="true">🌙</span></button>
    <div class="cl-hero-main">
      <h1 class="cl-hero-title">Jevil</h1>
      <p class="cl-hero-sub">Few-time signature · degree-D polynomial secret · Goldilocks field</p>
      <p class="cl-hero-desc">Sign messages that reveal evaluations of a secret degree-D polynomial, then watch anyone Lagrange-interpolate the whole secret key the instant the distinct revealed points reach D+1.</p>
    </div>
    <aside class="cl-hero-why" aria-label="Why it matters">
      <span class="cl-hero-why-label">WHY IT MATTERS</span>
      <p class="cl-hero-why-text">Few-time schemes are supposed to degrade gracefully. Jevil instead fails off a cliff. In the paper's full construction and recommended parameters, signatures through <code>n*</code> target about 124-bit classical security; signature <code>n*+1</code> makes the secret polynomial recoverable outright. It shows why a hard usage bound can be a catastrophe, not a warning.</p>
    </aside>
  </header>

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
            <option value="16">16 — the paper&rsquo;s parameter value</option>
          </select>
        </label>
        <label>Field
          <select id="sel-field">
            <option value="base" selected>base — Goldilocks (legible)</option>
            <option value="tower">tower — F(q₀⁴) ≈ 2²⁵⁶ (paper)</option>
          </select>
        </label>
        <label>Signer
          <select id="sel-signer">
            <option value="honest" selected>honest</option>
            <option value="malicious">malicious (uncommitted)</option>
          </select>
        </label>
        <button id="btn-gen" class="btn btn-primary">Generate key</button>
      </div>
      <p id="param-pending" class="note pending hidden" role="status" aria-live="polite"></p>
      <p class="note">
        &#9432; <strong>Small params for visual clarity.</strong> Tiny
        <code>n*</code>/<code>K</code> keep the point count legible;
        <code>K=16</code> is the value the paper uses &mdash; but <code>K</code>
        alone does not make a configuration secure: the full parameter set, the
        zk-WHIR commitment, the random-oracle encoding and the proof system do,
        and this page ships none of the last three. <strong>Field</strong>
        swaps the legible 64-bit base field for the paper's degree-4 tower
        <code>F(q₀⁴) ≈ 2²⁵⁶</code> (same cliff, bigger numbers).
        <strong>Malicious</strong> models a signer the real scheme's zk-WHIR
        commitment would forbid — see what its absence allows in panel 04.
      </p>
      <div id="key-out" class="key-out hidden"></div>
    </section>

    <section class="panel" id="panel-sign">
      <div class="panel-head"><span class="panel-num" aria-hidden="true">02</span><h2>Sign messages</h2></div>
      <p class="panel-intro">
        Each signature reveals <code>K</code> evaluations of <code>f</code> at
        hash-derived positions. Honest signing takes whatever the message hashes
        to — and often re-hits positions it has used before, so an honest signer
        can sign well past <code>n*</code> times before nearing the cliff. The
        <span class="danger-text">grind</span> is the <strong>adversarial worst
        case</strong>: an attacker picks messages whose positions are all
        <em>fresh</em>, packing the ledger as fast as possible to reach the cliff
        in exactly <code>n*+1</code> signatures. That worst case is what
        <code>n*</code> budgets for.
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
      <p class="panel-intro">
        <strong>From the revealed evaluations alone</strong>, fewer than
        <code>D+1</code> distinct points do not determine <code>f</code>: with
        <code>m</code> distinct points, exactly
        <code>|F|<sup>D+1&minus;m</sup></code> degree-<code>D</code> polynomials fit
        them &mdash; a large finite number, not &ldquo;infinitely many&rdquo;; this
        is a finite field &mdash; and those equations rank every one equally. Reach
        <code>D+1</code> and that count collapses to <strong>one</strong>: the
        answer snaps from <em>underdetermined</em> to <em>certain</em> in a single
        signature. That discontinuity is the cliff.
      </p>
      <p class="note scope-note">
        &#9432; <strong>Scope.</strong> &ldquo;Underdetermined&rdquo; is a statement
        about the <em>evaluation equations</em>, not about this demo's whole public
        key. The key also publishes a binding fingerprint of the coefficients and
        derives them deterministically from a seed, so an adversary with unbounded
        computing power can enumerate seeds and test them against that fingerprint.
        Say <em>algebraically underdetermined</em> below the cliff,
        <em>computationally protected</em> by the commitment and hash assumptions,
        and <em>catastrophically recovered</em> at <code>D+1</code>.
      </p>
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
          <span id="plot-candidates">many</span>. At <code>D+1</code> points they
          collapse to one. The
          curve shapes are an illustration; the binding proof is the exact
          coefficient match in panel 04.
        </figcaption>
      </figure>
    </section>

    <section class="panel danger-panel hidden" id="panel-recover">
      <div class="panel-head"><span class="panel-num" aria-hidden="true">04</span><h2>Secret recovered</h2></div>
      <p class="panel-intro">
        The key the signer believed was private, reconstructed from public data
        alone. Recovered coefficients (left) vs. the true secret (right),
        compared row by row — live, in your browser.
        <strong>Whoever holds <code>f</code> can now forge a valid signature on
        any message</strong>: the recoverer has become the signer. The private
        key is public, and the signer can never take it back.
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
      <div class="export-row">
        <button id="btn-export" class="btn">Export public recovery transcript &amp; check</button>
        <p class="export-hint">
          Downloads only public data (params, OOD pair, revealed points, key
          fingerprint — <strong>no secret</strong>), then re-checks it here. It
          audits <em>interpolation and fingerprint consistency</em> — not which
          messages were signed, how many signing operations produced the points,
          or that they came from accepted signatures. Audit it yourself offline:
          <code>npm run verify &lt;file&gt;</code>, or
          <code>npm run verify &lt;file&gt; --expected-fingerprint &lt;fp&gt;</code>
          to anchor it to a fingerprint you already trust.
        </p>
      </div>
      <p id="export-result" class="hint" role="status" aria-live="polite"></p>
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
          <span class="cmp-note"><strong>Schematic, not measured.</strong> The two
          lines are not on comparable footings: the soft curve is the HORS bound
          <em>evaluated at this demo's tiny <code>T</code></em> (real FORS uses a
          far larger <code>T</code>, so its slope stays low much longer), while the
          Jevil line is the paper's claim for its full construction. The Jevil line
          is drawn along the axis because a ~2<sup>&minus;124</sup> probability is
          <em>negligible, not zero</em> — on a linear axis nothing else would be
          visible. This demo does not measure a forgery probability for either
          scheme; it shows the shape of the two failure modes.</span>
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
        Per the paper's Table 1, Jevil is &mdash; <em>to the author's
        knowledge</em> &mdash; the first <strong>post-quantum, transparent,
        sharp-cliff, count-triggered</strong> few-time signature scheme, combining
        properties no prior FTS offered together. That priority claim is the
        paper's, not this lab's, and it is a recent preprint.
      </p>
    </section>

    <section class="prose callout-real">
      <h2>What's real, what's illustrative</h2>
      <p>
        The cliff is faithful: real finite-field arithmetic, hash-derived
        positions, an accumulating distinct-point ledger, and genuine
        <code>O(D&sup2;)</code> Lagrange recovery that is verified to reproduce the
        true secret exactly. The plot is a real-number <em>geometric</em>
        illustration.
      </p>
      <p>
        The load-bearing omission is the <strong>zk-WHIR polynomial
        commitment</strong> — what makes the cliff binding on a <em>malicious</em>
        signer. Without it, a cheating signer could quietly use a
        higher-degree polynomial than declared, so the public points never reach
        <code>D+1</code> and the cliff never fires — they could oversign forever.
        The real scheme's commitment binds the degree and shuts that door; this
        demo shows the cliff <em>geometry</em> and trusts the signer to use a
        genuine degree-<code>D</code> key. Full honesty in
        <a href="https://github.com/systemslibrarian/crypto-lab-jevil/blob/main/KNOWN-GAPS.md" target="_blank" rel="noopener"><code>KNOWN-GAPS.md</code></a>.
      </p>
    </section>

    <section class="prose">
      <details class="glossary">
        <summary>Glossary — the jargon, briefly</summary>
        <dl>
          <dt>Few-time signature (FTS)</dt>
          <dd>A signature key that is only safe to use a fixed number of times.</dd>
          <dt>Budget <code>n*</code></dt>
          <dd>How many signatures this key can safely produce before failing.</dd>
          <dt>HORS</dt>
          <dd>&ldquo;Hash to Obtain a Random Subset&rdquo; — the scheme family where each signature reveals a hash-selected subset of secret values. FORS, inside SLH-DSA / SPHINCS+, is the <em>soft</em>-failing cousin.</dd>
          <dt>Out-of-domain (OOD) point</dt>
          <dd>One free evaluation of <code>f</code> published in the key — the head start that fixes the cliff at <code>n*+1</code>.</dd>
          <dt>Degree <code>D</code> &middot; coefficients</dt>
          <dd>The secret is a polynomial <code>f</code> of degree <code>D</code>; its <code>D+1</code> coefficients <em>are</em> the private key.</dd>
          <dt>Lagrange interpolation</dt>
          <dd>The standard method to reconstruct the unique degree-<code>D</code> polynomial through <code>D+1</code> points — the engine of the cliff.</dd>
          <dt>Goldilocks field</dt>
          <dd>Arithmetic modulo the prime <code>q&#8320; = 2&#8310;&#8308; &minus; 2&#179;&#178; + 1</code>; every number here lives in it.</dd>
          <dt>Forgery &middot; EUF-CMA</dt>
          <dd>Producing a valid signature on a message you were never authorized to sign. Recovering <code>f</code> makes forgery trivial.</dd>
          <dt>Post-quantum &middot; transparent</dt>
          <dd>Secure against quantum computers (hash-based, no number theory) and requiring no trusted setup.</dd>
          <dt>zk-WHIR commitment</dt>
          <dd>The polynomial commitment (not built in this demo) that forces even a cheating signer to use a genuine degree-<code>D</code> key.</dd>
        </dl>
      </details>
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
      <p>Related demos:
        <a href="https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/" target="_blank" rel="noopener">crypto-lab-sphincs-ledger</a> ·
        <a href="https://systemslibrarian.github.io/crypto-lab-lms-ledger/" target="_blank" rel="noopener">crypto-lab-lms-ledger</a> ·
        <a href="https://systemslibrarian.github.io/crypto-lab-lms-xmss/" target="_blank" rel="noopener">crypto-lab-lms-xmss</a> ·
        <a href="https://systemslibrarian.github.io/crypto-lab-mpcith-sign/" target="_blank" rel="noopener">crypto-lab-mpcith-sign</a> ·
        <a href="https://systemslibrarian.github.io/crypto-lab-dilithium-seal/" target="_blank" rel="noopener">crypto-lab-dilithium-seal</a>
      </p>
      <p>So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31</p>
    </footer>
  </main>`;
}

// ------------------------------------------------------------- handlers ----

/**
 * The four selectors are inputs to *Generate key*, not live controls — but
 * nothing said so, so flipping n* or the signer left every panel below
 * describing a key those settings no longer produce, with the meter, the cliff
 * callout and the recovery verdict all reading as if they were about the
 * selection on screen. Say plainly which key the page is talking about.
 */
function syncPendingParams(): void {
  const el = $("#param-pending");
  if (!key) {
    el.classList.add("hidden");
    el.textContent = "";
    return;
  }
  const wantNStar = parseInt($<HTMLSelectElement>("#sel-nstar").value, 10);
  const wantK = parseInt($<HTMLSelectElement>("#sel-k").value, 10);
  const wantField = $<HTMLSelectElement>("#sel-field").value;
  const wantSigner = $<HTMLSelectElement>("#sel-signer").value;
  const haveField = key.field === GF4 ? "tower" : "base";
  const haveSigner = key.degreeBoost > 0 ? "malicious" : "honest";

  const pending =
    wantNStar !== key.params.nStar ||
    wantK !== key.params.K ||
    wantField !== haveField ||
    wantSigner !== haveSigner;

  el.classList.toggle("hidden", !pending);
  el.innerHTML = pending
    ? `&#9432; <strong>Parameters changed — press <em>Generate key</em> to apply.</strong>
       Everything below still describes the key in play:
       <code>n*=${key.params.nStar}</code>, <code>K=${key.params.K}</code>,
       ${haveField} field, ${haveSigner} signer.`
    : "";
}

async function doGenerate() {
  const nStar = parseInt($<HTMLSelectElement>("#sel-nstar").value, 10);
  const K = parseInt($<HTMLSelectElement>("#sel-k").value, 10);
  const F: Field<any> = $<HTMLSelectElement>("#sel-field").value === "tower" ? GF4 : GF;
  const malicious = $<HTMLSelectElement>("#sel-signer").value === "malicious";
  const boost = malicious ? 1 : 0;
  const seed = randomSeed();
  key = await keyGen(F, nStar, K, seed, boost);
  ledger = new Ledger(key);
  grindNonce = 0;

  const p = key.params;
  const trueDeg = p.D + boost;
  const fieldNote = F === GF4
    ? `the paper's tower <code>F(q&#8320;&#8308;) &approx; 2&#178;&#8309;&#8310;</code>`
    : `the Goldilocks base field <code>q&#8320; = 2&#8310;&#8308; &minus; 2&#179;&#178; + 1</code>`;
  const secretLine = malicious
    ? `<p class="secret-line malicious-line">&#9888; <strong>Malicious signer.</strong>
        The public key advertises degree <code>${p.D}</code>, but the secret is
        actually degree <code>${trueDeg}</code> (${p.M + boost} coefficients).
        Nothing here forces the signer to be honest — the real scheme's zk-WHIR
        commitment does. Watch the cliff <em>fail to recover</em> in panel 04.</p>`
    : `<p class="secret-line">Secret: a degree-${p.D} polynomial &mdash; ${p.M}
        hidden coefficients over ${fieldNote}.</p>`;

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
      Public out-of-domain freebie&nbsp; <span class="ood-pair">(z=${key.field.fmt(key.ood.x)}, f(z)=${key.field.fmt(key.ood.y)})</span>
      &mdash; one free point on <code>f</code>, baked into the public key. It is
      not decoration: it counts as one of the <code>D+1</code> points an attacker
      needs, the head start that makes the cliff land at exactly signature
      <code>n*+1</code>.
    </p>
    <p class="fp-line">
      Public key fingerprint&nbsp;
      <code id="key-fingerprint" class="fp-value">${key.fingerprint}</code>
      &mdash; a binding hash of the coefficient vector, published with the key.
      This is the <strong>trust anchor</strong>: an offline verifier that has this
      value from an independent source can tell whether a transcript really
      belongs to <em>this</em> key. A transcript checked only against the copy
      inside its own file proves consistency, not provenance.
    </p>
    ${secretLine}`;

  $("#sign-hint").textContent = "";
  $("#recover-out").innerHTML = "";
  $("#export-result").className = "hint";
  $("#export-result").textContent = "";
  exportStamp = null;
  $("#panel-recover").classList.add("hidden");
  // Soft-vs-sharp comparison depends only on the chosen params.
  $("#compare").innerHTML = renderCompare(key.params);
  syncPendingParams();
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
  grindNonce += dr.noncesTried; // resume at the next untried nonce
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

function reportSign(fresh: number, before: number, after: CliffStatus<any>, label: string) {
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

function doExport() {
  if (!key || !ledger) return;
  const transcript = exportTranscript(key, ledger);
  const json = JSON.stringify(transcript, null, 2);
  const blob = new Blob([json], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `jevil-transcript-${key.rootHint}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);

  // Re-check the just-exported public transcript, in the browser, to prove the
  // round-trip works from public data alone.
  const r = verifyTranscript(transcript);
  const el = $("#export-result");
  exportStamp = ledgerStamp;
  if (r.ok) {
    // NOT "Verified". The fingerprint this compares against is the one inside
    // the file that was just exported, so a transcript from ANY other key passes
    // the identical check — measured in scripts/core.test.ts. Calling that
    // "Verified" claims a provenance the check does not establish.
    el.className = "hint export-ok";
    el.innerHTML =
      `&#10003; <strong>Internally consistent.</strong> The key was reconstructed from ` +
      `${r.distinct} public points, and its hash equals the fingerprint stored in the same file ` +
      `(<code>${transcript.fingerprint.slice(0, 16)}…</code>). That proves recovery came from ` +
      `public data &mdash; <strong>not</strong> that this file belongs to the key above; a transcript ` +
      `exported from any other key passes this same check. Anchor it by running ` +
      `<code>npm run verify &lt;file&gt; --expected-fingerprint …</code> with the fingerprint copied ` +
      `from the key panel above, not from the file.`;
  } else {
    el.className = "hint export-bad";
    el.innerHTML = `&#9888; <strong>Not verified</strong> [${r.code}]: ${r.reason} (${r.distinct}/${r.needed} points).`;
  }
}

// --------------------------------------------------------- live update ----
function update() {
  if (!key || !ledger) return;
  const cliff = checkCliff(key, ledger);

  // Retire an export verdict that described an earlier ledger.
  ledgerStamp = `${key.rootHint}:${ledger.signatures.length}:${cliff.distinct}`;
  if (exportStamp !== null && exportStamp !== ledgerStamp) {
    exportStamp = null;
    const exportEl = $("#export-result");
    exportEl.className = "hint";
    exportEl.textContent =
      "The ledger has changed since that export — export again to re-verify against the points on screen now.";
  }

  // Meter (also exposed as an ARIA progressbar).
  const pct = Math.min(100, (cliff.distinct / cliff.needed) * 100);
  const fill = $("#meter-fill");
  fill.style.width = pct.toFixed(1) + "%";
  fill.className = "meter-fill " + meterClass(pct, cliff.reached);
  $("#meter-count").textContent = `${cliff.distinct} / ${cliff.needed}`;
  const meter = $("#meter");
  meter.setAttribute("aria-valuemax", String(cliff.needed));
  // Honest signing can push distinct past needed; clamp so valuenow stays a
  // valid progressbar value within [valuemin, valuemax].
  meter.setAttribute("aria-valuenow", String(Math.min(cliff.distinct, cliff.needed)));
  const escaped = cliff.reached && key.degreeBoost > 0;
  meter.setAttribute(
    "aria-valuetext",
    `${cliff.distinct} of ${cliff.needed} distinct points` +
      (cliff.reached
        ? escaped
          ? " — cliff reached, but the malicious key escaped"
          : " — cliff reached, secret recovered"
        : ""),
  );

  // Disable the grind once the cliff has fired (the secret is already public,
  // or — for a malicious key — has provably escaped the advertised cliff).
  const grind = $<HTMLButtonElement>("#btn-grind");
  grind.disabled = cliff.reached;
  grind.setAttribute("aria-disabled", String(cliff.reached));

  // How many degree-D polynomials still fit the revealed evaluations. Computed
  // from the live field size and point count — the page used to say "infinitely
  // many", which is false in a finite field, and printed it unconditionally.
  const candidates = candidateCount(key.field, key.params.D, cliff.distinct);
  const candText = cliff.distinct >= cliff.needed
    ? "exactly one"
    : `${formatCount(candidates)} of them`;
  const pc = document.getElementById("plot-candidates");
  if (pc) pc.textContent = candText;

  // Status callout.
  const status = $("#cliff-status");
  if (escaped) {
    status.className = "cliff-status escaped shake";
    status.innerHTML =
      `&#9888; <strong>Cliff fired — but the key escaped.</strong> ${cliff.distinct} points reached ` +
      `D+1 = ${cliff.needed}, yet the recovered degree-${key.params.D} polynomial is <em>not</em> the ` +
      `signer's key (it is secretly degree ${key.params.D + key.degreeBoost}). The cheater oversigned and stayed hidden.`;
  } else if (cliff.reached) {
    status.className = "cliff-status danger shake";
    status.innerHTML =
      `&#9888; <strong>Secret recovered.</strong> ${cliff.distinct} distinct points &ge; D+1 = ${cliff.needed}. ` +
      `The polynomial is uniquely determined and reconstructed below.`;
  } else {
    status.className = "cliff-status safe";
    const left = cliff.needed - cliff.distinct;
    status.innerHTML =
      `&#128274; <strong>Algebraically underdetermined.</strong> ${cliff.distinct} of ${cliff.needed} ` +
      `points &mdash; ${left} short. Exactly ${formatCount(candidates)} degree-${key.params.D} ` +
      `polynomials still fit these evaluations.`;
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

const GAPS_LINK =
  "https://github.com/systemslibrarian/crypto-lab-jevil/blob/main/KNOWN-GAPS.md";

function renderRecovery(cliff: CliffStatus<any>) {
  const panel = $("#panel-recover");
  if (!cliff.reached || !cliff.recovered || !key) {
    panel.classList.add("hidden");
    return;
  }
  panel.classList.remove("hidden");
  const F = key.field;
  const title = $("#panel-recover h2");
  const intro = $("#panel-recover .panel-intro");

  // Malicious key: the advertised cliff fired but recovered the wrong polynomial.
  if (key.degreeBoost > 0) {
    title.textContent = "Signer escaped the cliff";
    intro.classList.add("hidden");
    const real = key.params.D + key.degreeBoost;
    $("#recover-out").innerHTML = `
      <div class="verdict escaped" role="status">SIGNER ESCAPED &mdash; the cliff did not recover the key.</div>
      <p class="escape-note">At the advertised cliff (<code>D+1 = ${cliff.needed}</code> points)
        anyone can interpolate the unique degree-<code>${key.params.D}</code> polynomial through the
        public points — but the signer's real key is degree <code>${real}</code>, so that interpolation
        is the <em>wrong</em> polynomial. The key stays secret, and the signer has oversigned past
        <code>n*</code> with impunity. (It would take <code>${real + 1}</code> points to pin down the
        real key — more than the budget yields.)</p>
      <p class="escape-note"><strong>This is exactly what the zk-WHIR commitment prevents.</strong>
        It binds the public key to a genuine degree-<code>${key.params.D}</code> polynomial, so a signer
        can't smuggle in extra degree to dodge the cliff. The demo omits that commitment
        (<a href="${GAPS_LINK}" target="_blank" rel="noopener">why</a>) precisely so you can see what its
        absence would allow.</p>`;
    return;
  }

  // Honest key: show the coefficient diff (capped for large M).
  title.textContent = "Secret recovered";
  intro.classList.remove("hidden");
  const recovered = cliff.recovered;
  const total = key.coeffs.length;
  const MAX_ROWS = 24;
  const shown = Math.min(total, MAX_ROWS);
  const rows = key.coeffs
    .slice(0, shown)
    .map((trueC: any, i: number) => {
      const rec = recovered[i];
      const match = F.eq(rec, trueC);
      return `<tr class="${match ? "match" : "mismatch"}">
        <th scope="row" class="idx">c<sub>${i}</sub></th>
        <td class="mono">${F.fmtFull(rec)}</td>
        <td class="cmp" aria-label="${match ? "matches" : "differs"}"><span aria-hidden="true">${match ? "&#10003;" : "&#10007;"}</span></td>
        <td class="mono">${F.fmtFull(trueC)}</td>
      </tr>`;
    })
    .join("");
  const moreRow =
    total > shown
      ? `<tr class="more-row"><td colspan="4">… and ${total - shown} more coefficients (all match)</td></tr>`
      : "";
  const verdict = cliff.exact
    ? `<div class="verdict exact" role="status">EXACT MATCH &mdash; all ${total} coefficients reconstructed from public data.</div>`
    : `<div class="verdict bad" role="status">MISMATCH &mdash; recovery did not reproduce the secret.</div>`;
  $("#recover-out").innerHTML = `
    ${verdict}
    <div class="table-scroll" tabindex="0" role="region" aria-label="Recovered coefficients versus true secret (scrollable)">
      <table class="coeff-table">
        <caption class="sr-only">Each row compares a recovered coefficient with the true secret coefficient.</caption>
        <thead><tr><th scope="col">coeff</th><th scope="col">recovered (from public data)</th><th scope="col"><span class="sr-only">match</span></th><th scope="col">true secret</th></tr></thead>
        <tbody>${rows}${moreRow}</tbody>
      </table>
    </div>`;
}

function renderLedger() {
  if (!ledger || !key) return;
  const F = key.field;
  const seen = new Set<string>();
  const out: string[] = [];

  // OOD freebie.
  seen.add(F.fmtFull(key.ood.x));
  out.push(`
    <div class="led-group ood-group">
      <div class="led-tag">OOD freebie &middot; baked into public key</div>
      <div class="led-points">
        <span class="led-pt ood-pt">x=${F.fmt(key.ood.x)} &middot; f(x)=${F.fmt(key.ood.y)}</span>
      </div>
    </div>`);

  ledger.signatures.forEach((s: any) => {
    const pts = s.points
      .map((p: any) => {
        const k = F.fmtFull(p.x);
        const dup = seen.has(k);
        if (!dup) seen.add(k);
        return `<span class="led-pt ${dup ? "dup" : ""}" title="position index i=${p.index}">
          x=${F.fmt(p.x)} &middot; f(x)=${F.fmt(p.y)}${dup ? " &middot;dup" : ""}</span>`;
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
  const generate = guard(doGenerate);
  const signHonest = guard(doSignHonest);
  $("#btn-gen").addEventListener("click", generate);
  $("#btn-sign").addEventListener("click", signHonest);
  $("#btn-grind").addEventListener("click", guard(doGrind));
  $("#btn-export").addEventListener("click", doExport);
  for (const sel of ["#sel-nstar", "#sel-k", "#sel-field", "#sel-signer"]) {
    $(sel).addEventListener("change", syncPendingParams);
  }
  // Press Enter in the message field to sign honestly.
  $("#msg").addEventListener("keydown", (e) => {
    if ((e as KeyboardEvent).key === "Enter") {
      e.preventDefault();
      signHonest();
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

  generate();
}

boot();
