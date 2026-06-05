// src/lagrange.ts — the cliff engine, generic over any Field<T>.
//
// A degree-D polynomial is uniquely determined by D+1 distinct points. Below
// that count, infinitely many degree-D polynomials fit and the secret
// coefficients are information-theoretically hidden; at exactly D+1 distinct
// points the answer snaps to a unique polynomial recoverable in O(D²) field
// operations (paper Theorem 1 / Theorem 2).

import type { Field } from "./ff";

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
