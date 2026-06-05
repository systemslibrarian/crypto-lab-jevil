# crypto-lab-jevil

## 1. What It Is

**Jevil** is a *few-time signature* (FTS) scheme — a digital signature whose key
is only safe to use a fixed number of times, `n*`. Its secret key is the
coefficient vector of a random degree-`D` polynomial `f` over the 64-bit
Goldilocks field; each signature reveals `K` hash-derived evaluations of `f`
(the HORS "hash to obtain a random subset" idea), and the public key ships one
free out-of-domain evaluation. The problem it solves is *enforcing a hard signing
cap*: unlike HORS-family schemes (FORS in SLH-DSA) that degrade softly, Jevil
fails off a **cliff** — the moment the distinct revealed points cross `D+1`,
anyone can Lagrange-interpolate the whole secret key in `O(D²)` field operations.
It is **post-quantum** (hash-based, no number-theoretic hardness) and
**transparent** (no trusted setup); it is *not* an encryption scheme and, as
realized in this repo, it demonstrates the cliff *geometry* rather than the full
commitment-bound scheme (see [`KNOWN-GAPS.md`](./KNOWN-GAPS.md)).

## 2. When to Use It

- **Firmware vendors capping signed releases per key** — the budget `n*` is the
  security property; exceeding it must be undeniable, which the cliff guarantees.
- **Per-tenure attestation budgets** — an authority allowed to attest exactly
  `n*` times leaks its key if it tries an `(n*+1)`-th, making over-attestation
  self-punishing.
- **Ephemeral session signers** — a short-lived signer with a built-in,
  self-enforcing usage limit needs no external counter to be trusted.
- **Audit-budgeted credentials** — where the *signer*, not the verifier, should
  bear the cost of breaking the cap; oversigning fails loudly and against the
  signer.
- **When NOT to use it:** anything needing many signatures from one key — reach
  for a standard scheme like ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) instead;
  Jevil's whole point is that signature `n*+1` is catastrophic, not merely
  weaker.

## 3. Live Demo

**→ <https://systemslibrarian.github.io/crypto-lab-jevil/>**

Generate a key, then either **Sign (honest)** a message or **Grind toward
cliff** — the adversarial mode that packs the public ledger with disjoint
points as fast as possible. Watch the distinct-point meter climb and, the
instant it reaches `D+1`, see the secret key reconstructed live from public data
with an exact-match check. This is a *signature* demo (no encrypt/decrypt); the
controls are the budget `n*`, the positions-per-signature `K`, the **field**
(legible base field or the paper's `F(q₀⁴) ≈ 2²⁵⁶` tower), and the **signer**
(honest, or a malicious uncommitted higher-degree key that escapes the cliff —
showing what the zk-WHIR commitment prevents).

**Auditable, not just convincing.** Use **Export public transcript** to download
a JSON file containing *only public data* — params, the OOD pair, the revealed
points, and a binding fingerprint of the key (no secret). Anyone can then
reconstruct the key from that file alone and check it against the fingerprint:

```bash
npm run verify path/to/jevil-transcript.json
```

A `VERIFIED` result proves the key fell out of public data — the recovery is not
a stored answer. (A malicious/over-degree transcript verifies as `NOT VERIFIED`.)

## 4. How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-jevil
cd crypto-lab-jevil
npm install
npm run dev
```

No environment variables are required.

```bash
npm test          # crypto-core faithfulness proof (both fields + malicious mode)
npm run test:e2e  # browser regression suite (Playwright + axe-core, WCAG 2.1 AA)
npm run build     # produce the static site
```

CI runs the core test, the build, and the e2e suite on every push
(`.github/workflows/verify.yml`) and deploys to GitHub Pages
(`deploy.yml`).

## 5. Part of the Crypto-Lab Suite

One of 60+ live browser demos at
[systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/)
— spanning Atbash (600 BCE) through NIST FIPS 203/204/205 (2024).

---

*"Whether you eat or drink, or whatever you do, do all to the glory of God." — 1 Corinthians 10:31*
