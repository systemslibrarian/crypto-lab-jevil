// src/lagrange.ts — the cliff engine, generic over any Field<T>.
//
// A degree-D polynomial is uniquely determined by D+1 distinct points. Below
// that count the revealed evaluations do not pin it down: with m distinct points
// out of the D+1 needed, exactly |F|^(D+1−m) degree-D polynomials fit them, and
// from those evaluations ALONE every one is equally likely. At exactly D+1
// distinct points that count collapses to 1 and the answer is recoverable in
// O(D²) field operations (paper Theorem 1 / Theorem 2).
//
// Note the two scopes, which the page used to run together:
//   - "|F|^(D+1−m) fit" is a statement about the EVALUATION EQUATIONS. It is a
//     finite number, not "infinitely many" — this is a finite field.
//   - It is NOT a statement about this implementation's whole public key, which
//     also publishes a binding fingerprint of the coefficients and derives them
//     from an enumerable seed. See candidateCount's note and KNOWN-GAPS.md.

import type { Field } from "./ff";

/**
 * How many degree-D polynomials are consistent with `distinct` revealed
 * evaluations. Each unused degree of freedom ranges over the whole field, so
 * the count is |F|^(D+1−distinct), and it is 1 once distinct reaches D+1.
 *
 * This is the number the page prints. It is deliberately EXACT rather than the
 * word "infinitely many": the scheme lives in a finite field, so the set of
 * consistent polynomials is finite and countable, and saying so is both true and
 * more informative than the false version.
 *
 * SCOPE: this counts solutions of the evaluation equations only. An adversary
 * who also uses the published key fingerprint — a binding commitment to the
 * coefficient vector — can test candidates against it, so this count is not a
 * claim about what an unbounded adversary can learn from the whole public key.
 */
export function candidateCount<T>(F: Field<T>, D: number, distinct: number): bigint {
  const freeDims = Math.max(0, D + 1 - distinct);
  return F.size ** BigInt(freeDims);
}

/** "2^704" / "1" — a readable magnitude for a candidate count. */
export function formatCount(n: bigint): string {
  if (n <= 1n) return "1";
  const bits = n.toString(2).length - 1;
  return `2^${bits}`;
}

export interface Point<T> {
  x: T;
  y: T;
}

/** Keep one point per distinct x (first occurrence wins) — only distinct
 *  positions advance the cliff (paper §5.2–5.3). Keyed by the field's canonical
 *  string form. */
export function dedupeByX<T>(F: Field<T>, points: Point<T>[]): Point<T>[] {
  const seen = new Set<string>();
  const out: Point<T>[] = [];
  for (const p of points) {
    const key = F.fmtFull(p.x);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(p);
  }
  return out;
}

export function distinctCount<T>(F: Field<T>, points: Point<T>[]): number {
  return new Set(points.map((p) => F.fmtFull(p.x))).size;
}

/**
 * Lagrange interpolation expanded into the monomial (coefficient) basis. Given
 * exactly D+1 distinct points, returns the unique degree-D coefficient vector
 * [c0, …, cD] (low-order first) in O(D²) field operations — the actual secret
 * polynomial, not just one evaluation.
 *
 *   f(x) = Σ_i  y_i · Π_{j≠i} (x − x_j) / (x_i − x_j)
 */
export function interpolateCoeffs<T>(F: Field<T>, points: Point<T>[]): T[] {
  const pts = dedupeByX(F, points);
  const n = pts.length;
  if (n === 0) return [];

  const coeffs: T[] = new Array(n).fill(F.zero);

  for (let i = 0; i < n; i++) {
    // numerator polynomial Π_{j≠i} (x − x_j), coefficients low-order first
    const basis: T[] = new Array(n).fill(F.zero);
    basis[0] = F.one;
    let degree = 0;

    let denom = F.one;
    for (let j = 0; j < n; j++) {
      if (j === i) continue;
      const xj = pts[j].x;
      // multiply basis by (x − xj): b'[k] = b[k−1] − xj·b[k], high→low
      for (let k = degree + 1; k >= 1; k--) {
        basis[k] = F.sub(basis[k - 1], F.mul(xj, basis[k]));
      }
      basis[0] = F.sub(F.zero, F.mul(xj, basis[0]));
      degree++;
      denom = F.mul(denom, F.sub(pts[i].x, xj));
    }

    const scale = F.mul(pts[i].y, F.inv(denom));
    for (let k = 0; k <= degree; k++) {
      coeffs[k] = F.add(coeffs[k], F.mul(basis[k], scale));
    }
  }

  return coeffs;
}

/** Are two coefficient vectors equal as field elements? */
export function coeffsEqual<T>(F: Field<T>, a: T[], b: T[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (!F.eq(a[i], b[i])) return false;
  }
  return true;
}
