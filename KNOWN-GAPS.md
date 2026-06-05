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
  cannot craft a public key that escapes the cliff or that commits to a
  higher-degree polynomial to buy extra signatures. This demo shows the cliff
  **geometry** — the Lagrange fact about honestly-generated keys — but **not the
  commitment that enforces it adversarially.** A demo signer is trusted to
  actually use a degree-`D` polynomial.
- **Base field instead of the tower.** The paper works in `F = F_{q₀⁴} ≈ 2²⁵⁶`,
  a degree-4 extension. We use the 64-bit base field `F_{q₀}` directly so the
  cliff stays exact and the numbers stay legible.
- **SHA-256 instead of SHAKE256 / Poseidon2.** The paper instantiates its random
  oracle `H_xof` with SHAKE256 (and uses an arithmetization-friendly hash inside
  the commitment). We use SHA-256 via Web Crypto as a faithful random-oracle
  stand-in, with the paper's domain-separation tags (`JV-SEED`, `JV-OOD`,
  `JV-POSN`, Table 6). No tag-padding/length-encoding details are modeled.
- **The plot is a real-number geometric illustration.** Over Goldilocks,
  plotting `f(g^i)` does not produce a smooth curve. So Panel 03 renders the
  cliff geometry in real-number coordinate space: the degree `D` and the
  revealed-point count are driven by live scheme state, the "infinitely many
  fit" curves are genuine real-number interpolants through the revealed points,
  and the collapse to one curve at `D+1` is real — but the *values* are a
  legible illustration, not the Goldilocks field elements. The **binding**
  recovery proof (recovered `f` == true `f`) in Panel 04 uses the real field.
- **Tiny parameters for visibility.** `n* ∈ {1,2,3,5,7}` and `K ∈ {2,3,4}` keep
  the point count small. The paper restricts `n*` so that `n*+1` is a power of
  two (`{1,3,7,15,…}`); we relax this for the demo. No 124-bit parameters.
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
| `src/field.ts` | Goldilocks field arithmetic (faithful) |
| `src/lagrange.ts` | Distinct-point dedupe + `O(D²)` interpolation (faithful) |
| `src/hash.ts` | SHA-256 random-oracle: coeffs, OOD, positions (faithful mechanic, SHA-256 stand-in) |
| `src/jevil.ts` | KeyGen, sign, ledger, cliff check, grind attack (faithful) |
| `src/plot.ts` | SVG cliff plot (illustrative geometry) |
| `src/main.ts` | UI wiring |
| `scripts/core.test.ts` | Faithfulness proof (`npm test`) |
