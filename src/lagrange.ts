// src/lagrange.ts — the cliff engine.
//
// This is the heart of Jevil's "catastrophic failure by design". A degree-D
// polynomial is uniquely determined by D+1 distinct points. Below that count,
// infinitely many degree-D polynomials fit the data and the secret coefficients
// are information-theoretically hidden. At exactly D+1 distinct points the
// answer snaps to a unique polynomial — and anyone holding the public points can
// reconstruct it in O(D²) field operations (paper Theorem 1 / Theorem 2).

import { Q0, mod, mul, sub, inv } from "./field";

export interface Point {
  x: bigint;
  y: bigint;
}

/** Number of DISTINCT x-coordinates among the points. */
export function distinctCount(points: Point[]): number {
  const xs = new Set(points.map((p) => p.x.toString()));
  return xs.size;
}

/**
 * Keep one point per distinct x-coordinate (first occurrence wins).
 * An honest signer may revisit a position; only DISTINCT positions advance the
 * cliff (paper §5.2–5.3), so deduplication by x is part of the faithful model.
 */
export function dedupeByX(points: Point[]): Point[] {
  const seen = new Set<string>();
  const out: Point[] = [];
  for (const p of points) {
    const key = p.x.toString();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(p);
  }
  return out;
}

/**
 * Lagrange interpolation expanded into the monomial (coefficient) basis.
 *
 * Given exactly D+1 distinct points, returns the unique degree-D coefficient
 * vector [c0, c1, …, cD] (low-order first). Runs in O(D²) field operations — we
 * accumulate each Lagrange basis polynomial L_i(x) into the running coefficient
 * sum rather than evaluating at a single point, so the output is the actual
 * secret polynomial, not just one evaluation.
 *
 *   f(x) = Σ_i  y_i · Π_{j≠i} (x − x_j) / (x_i − x_j)
 */
export function interpolateCoeffs(points: Point[]): bigint[] {
  const pts = dedupeByX(points);
  const n = pts.length;
  if (n === 0) return [];

  // Accumulated coefficient vector for the full interpolant (degree n−1).
  const coeffs = new Array<bigint>(n).fill(0n);

  for (let i = 0; i < n; i++) {
    // Build the numerator polynomial  Π_{j≠i} (x − x_j)  incrementally.
    // `basis` holds its coefficients, low-order first. Start at the constant 1.
    const basis: bigint[] = new Array(n).fill(0n);
    basis[0] = 1n;
    let degree = 0;

    let denom = 1n;
    for (let j = 0; j < n; j++) {
      if (j === i) continue;
      const xj = pts[j].x;
      // Multiply basis by (x − xj). New coefficient at degree k is
      //   b'[k] = b[k−1] − xj·b[k]   (b[k−1] from the ×x term).
      // Walk high→low so b[k−1] is still the old value when we read it.
      for (let k = degree + 1; k >= 1; k--) {
        basis[k] = sub(basis[k - 1], mul(xj, basis[k]));
      }
      basis[0] = sub(0n, mul(xj, basis[0]));
      degree++;
      denom = mul(denom, sub(pts[i].x, xj));
    }

    // Scale by y_i / denom and add into the accumulator.
    const scale = mul(pts[i].y, inv(denom));
    for (let k = 0; k <= degree; k++) {
      coeffs[k] = mod(coeffs[k] + mul(basis[k], scale));
    }
  }

  return coeffs.map(mod);
}

/** Are two coefficient vectors equal as field elements? */
export function coeffsEqual(a: bigint[], b: bigint[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (mod(a[i]) !== mod(b[i])) return false;
  }
  return true;
}

// Re-export so callers needn't reach into field.ts for the modulus.
export { Q0 };
