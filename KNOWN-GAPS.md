# KNOWN-GAPS.md — what's faithful, what's illustrative

This demo exists to make **one idea** tangible: Jevil's *catastrophic cliff*.
Below `D+1` distinct points a degree-`D` polynomial is information-theoretically
hidden; at `D+1` it snaps to a unique answer that anyone can reconstruct. That
fact is implemented for real. A working signature scheme it is **not**.

Source: M. Kobeissi, *"Jevil: A Few-Time Signature Scheme with Catastrophic
Failure by Design"*, Cryptology ePrint Archive Paper 2026/1103,
<https://eprint.iacr.org/2026/1103>.

> **This demo is for understanding the catastrophic-cliff idea, not for any real
> signing. Do not use it to protect anything.**

---

## Faithful (real, not faked)

- **Finite-field arithmetic** over the Goldilocks prime `q₀ = 2⁶⁴ − 2³² + 1`
  (paper §3.3). Every `add/sub/mul/pow/inv/div` is real `BigInt` modular
  arithmetic. Inversion is Fermat `a^(q₀−2)`. (`src/field.ts`)
- **Both the base field and the real degree-4 tower.** The whole scheme runs
  over a pluggable `Field<T>`, with two implementations: the legible 64-bit base
  field `F_{q₀}`, and the paper's actual `F_{q₀⁴} ≈ 2²⁵⁶` quartic extension
  (`u⁴ = 7`, the Plonky2 Goldilocks tower). The UI **Field** selector switches
  between them; the cliff recovers exactly over both. (`src/ff.ts`)
- **SHAKE256 random oracle.** `H_xof` is instantiated with SHAKE256 (paper
  Table 6) via the audited `@noble/hashes`, squeezed for coefficients, the OOD
  point, and positions, all domain-separated with the paper's tags
  (`JV-SEED`, `JV-OOD`, `JV-POSN`). (`src/hash.ts`)
- **The secret IS the polynomial.** The secret key is the coefficient vector of
  a random degree-`D` polynomial `f`, with `M = (n*+1)·K` coefficients,
  `D = M−1` (paper §4.1, Construction 1). (`src/jevil.ts`, `src/hash.ts`)
- **Hash-derived positions.** Each signature reveals `K` evaluations of `f` at
  positions `xₜ = g^{iₜ}` where the indices `iₜ` are derived from the message by
  a random oracle — the HORS "Hash to Obtain Random Subset" idea
  (paper Construction 2). (`src/hash.ts: derivePositions`)
- **The out-of-domain freebie.** The public key ships one free pair `(z, f(z))`
  baked in at KeyGen (paper Construction 1, step 4). It is a genuine extra point
  on `f` and it really does count toward the cliff. (`src/jevil.ts: keyGen`)
- **The accumulating distinct-point ledger.** Only *distinct* `x` advance the
  cliff; an honest signer may revisit a position and that duplicate does nothing
  (paper §5.2–5.3). (`src/lagrange.ts: dedupeByX`, `src/jevil.ts: Ledger`)
- **Real `O(D²)` Lagrange recovery.** At `D+1` distinct points we interpolate
  the unique polynomial via the Lagrange basis expanded into monomial
  coefficients — the same complexity the paper cites (Theorem 1/2).
  (`src/lagrange.ts: interpolateCoeffs`)
- **Verified exactness.** After recovery we check the reconstructed coefficient
  vector equals the *true* secret element-by-element. The "EXACT MATCH" verdict
  is that check, computed live — not a scripted reveal.
  (`src/jevil.ts: checkCliff`, `scripts/core.test.ts`)
- **Both timings.** Honest signing (positions are whatever the message hashes
  to) and the adversarial **disjoint-position grind** that packs `K` fresh
  points per signature and hits the cliff in exactly `ceil(M/K) = n*+1`
  signatures (paper §5.2). (`src/jevil.ts: findDisjointMessage`)

You can re-run the faithfulness proof: `npm test` builds a random degree-`D`
polynomial, samples points at `g^i`, and confirms `D+1` points recover `f`
exactly while `D` points do not — at the demo defaults *and* the real smallest
spec `n*=1, K=16 → D=31`.

---

## Illustrative / out of scope (and why it matters)

- **No zk-WHIR polynomial commitment — the load-bearing omission.** In the real
  scheme a polynomial commitment with degree-binding is what makes the cliff
  *binding on a malicious signer* (paper §6.1, "cap-binding"): a cheating signer
  cannot commit to a higher-degree polynomial to buy extra signatures. We do
  **not** implement WHIR (a research-grade hash-based commitment). Instead the
  **malicious-signer mode** *demonstrates what its absence allows*: select
  "malicious" and the signer secretly uses a degree-`(D+1)` key, so at the
  advertised cliff (`D+1` points) the interpolated degree-`D` polynomial is the
  *wrong* one and the key stays hidden — the cheater oversigns with impunity.
  The commitment is exactly what forbids this. (`src/jevil.ts` `degreeBoost`.)
- **Poseidon2 inside the (absent) commitment.** The paper also uses an
  arithmetization-friendly hash inside the commitment layer; with no commitment
  implemented, that hash has nothing to do here. No tag-padding / length-encoding
  details of `H_xof` are modeled either.
- **The soft-vs-sharp chart uses the classic HORS bound.** Panel 06 plots a
  soft few-time scheme's forgery probability as `(r·K / T)^K` after `r`
  signatures — the standard HORS/FORS bound — against Jevil's step function
  (negligible through `n*`, then 1 at `n*+1`). Both use the demo's live `K`/`T`.
  Real FORS uses a far larger `T`, so its slope stays low much longer; the small
  demo `T` only makes the curve's *shape* (gradual vs vertical) legible. The
  `~2^-124` floor below the cliff is asserted, not drawn to scale.
- **The plot is a real-number geometric illustration.** Over Goldilocks,
  plotting `f(g^i)` does not produce a smooth curve. So Panel 03 renders the
  cliff geometry in real-number coordinate space: the degree `D` and the
  revealed-point count are driven by live scheme state, the "infinitely many
  fit" curves are genuine real-number interpolants through the revealed points,
  and the collapse to one curve at `D+1` is real — but the *values* are a
  legible illustration, not the Goldilocks field elements. The **binding**
  recovery proof (recovered `f` == true `f`) in Panel 04 uses the real field.
- **Default parameters are tiny for visibility.** `n* ∈ {1..7}` and
  `K ∈ {2,3,4}` keep the point count legible; `K = 16` (the real security grade,
  `D = 31`+) is available via the selector but makes the plot/table dense. The
  paper restricts `n*` so that `n*+1` is a power of two (`{1,3,7,15,…}`); we
  relax that. We don't claim a specific bit-security level for any UI choice.
- **No signature serialization.** Real Jevil signatures are ~40 KB–500 KB
  (commitment openings); we keep evaluations as field elements in memory.
- **No formal security machinery.** No EUF-CMA hardness argument, no
  Fiat–Shamir batching, no Merkle multiproofs, no proof of the `~124-bit`
  existential-unforgeability bound for signatures `1..n*` (we assert it, the
  paper proves it).

---

## File map

| File | Role |
|------|------|
| `src/field.ts` | Goldilocks base-field arithmetic (faithful) |
| `src/ff.ts` | Pluggable `Field<T>`: base `F_{q₀}` + quartic tower `F_{q₀⁴}` (faithful) |
| `src/lagrange.ts` | Distinct-point dedupe + `O(D²)` interpolation, generic over the field (faithful) |
| `src/hash.ts` | SHAKE256 random oracle: coeffs, OOD, positions (faithful) |
| `src/jevil.ts` | KeyGen, sign, ledger, cliff check, grind, malicious mode (faithful) |
| `src/plot.ts` | SVG cliff plot (illustrative geometry) |
| `src/compare.ts` | Soft-vs-sharp chart, HORS bound (illustrative) |
| `src/main.ts` | UI wiring |
| `scripts/core.test.ts` | Faithfulness proof over both fields (`npm test`) |
