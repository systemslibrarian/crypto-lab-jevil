# crypto-lab-jevil

## What It Is

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

## When to Use It

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
- **Do NOT use it** for anything needing many signatures from one key — reach
  for a standard scheme like ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) instead;
  Jevil's whole point is that signature `n*+1` is catastrophic, not merely
  weaker, and this repo is a teaching demo of the cliff geometry.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-jevil](https://systemslibrarian.github.io/crypto-lab-jevil/)**

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

## What Can Go Wrong

- **Exceeding the budget is total, not partial.** Once the distinct revealed points reach `D+1`, anyone Lagrange-interpolates the entire secret key — there is no "slightly weaker" zone.
- **No graceful degradation.** Unlike soft-failing HORS/FORS, a few-time scheme with this cliff geometry has nothing between "safe" and "fully recovered."
- **Misconfigured `K` and `D` blow the cap early.** The larger `K` is relative to `D`, the fewer signatures it takes to accumulate `D+1` distinct points, so a bad parameter choice exhausts the budget faster than expected.
- **Without the commitment binding, the cliff can be dodged.** A malicious signer using an uncommitted higher-degree key escapes recovery; this repo shows that geometry but does not implement the full zk-WHIR commitment that prevents it (see `KNOWN-GAPS.md`).
- **"Few" must actually be enforced.** Reusing one key across contexts, or losing track of the count, can quietly cross the threshold and leak the key.

## Real-World Usage

- Few-time and one-time hash-based signatures — HORS, and the FORS layer inside SLH-DSA/SPHINCS+ (FIPS 205) — are deployed where post-quantum, setup-free signatures are needed.
- Hash-based signatures rest only on the security of hash functions, with no number-theoretic assumption for a quantum computer to break, which is why they anchor conservative PQ signature standards.
- Hard signing-cap semantics map to real needs: firmware-release budgets, attestation limits, and ephemeral signers that must self-enforce a usage count.
- The Goldilocks field (`2⁶⁴ − 2³² + 1`) used here is common in modern hash-based and STARK-friendly constructions because its arithmetic is fast.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-jevil
cd crypto-lab-jevil
npm install
npm run dev
```

## Related Demos

- [crypto-lab-sphincs-ledger](https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/) — SLH-DSA (SPHINCS+), the stateless hash-based signature whose FORS layer Jevil echoes.
- [crypto-lab-lms-ledger](https://systemslibrarian.github.io/crypto-lab-lms-ledger/) — LMS/HSS with W-OTS+, stateful hash-based signatures (NIST SP 800-208).
- [crypto-lab-lms-xmss](https://systemslibrarian.github.io/crypto-lab-lms-xmss/) — LMS and XMSS one-time-signature trees side by side.
- [crypto-lab-mpcith-sign](https://systemslibrarian.github.io/crypto-lab-mpcith-sign/) — MPC-in-the-Head signatures, another hash/symmetric-only PQ approach.
- [crypto-lab-dilithium-seal](https://systemslibrarian.github.io/crypto-lab-dilithium-seal/) — ML-DSA (FIPS 204), the many-time PQ signature to reach for instead.

## Testing

```bash
npm test          # crypto-core faithfulness proof (both fields + malicious mode)
npm run test:e2e  # browser regression suite (Playwright + axe-core, WCAG 2.1 AA)
npm run build     # produce the static site
```

CI runs the core test, the build, and the e2e suite on every push
(`.github/workflows/verify.yml`) and deploys to GitHub Pages
(`deploy.yml`).

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
