// src/jevil.ts — the Jevil few-time signature scheme, generic over Field<T>.
//
// Sources: Kobeissi, "Jevil", Cryptology ePrint 2026/1103. Construction 1
// (KeyGen + OOD freebie), Construction 2 (HORS positions), §4.1 (parameters),
// §5.2–5.3 (the disjoint-position grind), Theorem 1/2 (the cliff).
//
// The secret key IS the coefficient vector of a degree-D polynomial f. Each
// signature reveals K evaluations f(x_t) at hash-derived positions x_t = g^{i_t};
// the public key ships one free out-of-domain pair (z, f(z)). Once the DISTINCT
// revealed points reach D+1, anyone can Lagrange-interpolate f exactly.
//
// MALICIOUS MODE (degreeBoost > 0) models a signer the real scheme's zk-WHIR
// commitment would forbid: the public key advertises degree D, but the signer
// secretly uses degree D+boost. At the advertised cliff (D+1 points) the
// interpolated degree-D polynomial is NOT the real key — the cheater oversigned
// and stayed hidden. The commitment is exactly what prevents this; this demo
// omits it (see KNOWN-GAPS.md), so we can show what its absence would allow.

import type { Field } from "./ff";
import { deriveCoeffs, deriveOOD, derivePositions, hashId } from "./hash";
import {
  interpolateCoeffs,
  dedupeByX,
  coeffsEqual,
  type Point,
} from "./lagrange";

export interface Params {
  nStar: number; // signing budget chosen at KeyGen
  K: number; // positions revealed per signature
  M: number; // advertised coefficients = (n*+1)·K
  D: number; // advertised degree = M − 1
  T: number; // position domain size {0..T−1}
  nCliff: number; // signature at which the cliff fires = n*+1
}

export interface JevilKey<T> {
  params: Params;
  field: Field<T>;
  seed: string;
  coeffs: T[]; // THE SECRET (length M + degreeBoost)
  degreeBoost: number; // 0 = honest; >0 = malicious higher-degree key
  rootHint: string; // public per-key identifier
  ood: Point<T>; // public out-of-domain freebie (z, f(z))
}

export interface SignedPoint<T> extends Point<T> {
  index: number; // position index i_t (x = g^{i_t})
}

export interface Signature<T> {
  message: string;
  signatureNumber: number;
  points: SignedPoint<T>[];
  fresh: number; // how many x were new to the ledger when signed
}

/** Derive scheme parameters (paper §4.1). */
export function deriveParams(nStar: number, K: number): Params {
  const M = (nStar + 1) * K;
  return { nStar, K, M, D: M - 1, T: 2 * M, nCliff: nStar + 1 };
}

/** Evaluate a polynomial at x via Horner's method (low-order coeff first). */
export function evalPoly<T>(F: Field<T>, coeffs: T[], x: T): T {
  let acc = F.zero;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    acc = F.add(F.mul(acc, x), coeffs[i]);
  }
  return acc;
}

/** Position-to-field map psi(i) = g^i (paper Construction 2). */
export function psi<T>(F: Field<T>, i: number): T {
  return F.pow(F.generator, BigInt(i));
}

/** KeyGen (paper Construction 1): secret polynomial + public OOD freebie. */
export function keyGen<T>(
  F: Field<T>,
  nStar: number,
  K: number,
  seed: string,
  degreeBoost = 0,
): JevilKey<T> {
  const params = deriveParams(nStar, K);
  // True polynomial has M + degreeBoost coefficients; honest signer uses boost 0.
  const coeffs = deriveCoeffs(F, seed, params.M + degreeBoost);
  const rootHint = "jv-" + hashId(seed);
  const z = deriveOOD(F, rootHint);
  const w = evalPoly(F, coeffs, z); // f(z) — the freebie head start
  return { params, field: F, seed, coeffs, degreeBoost, rootHint, ood: { x: z, y: w } };
}

/** Sign honestly: positions are whatever the message hashes to. */
export function sign<T>(
  key: JevilKey<T>,
  message: string,
  signatureNumber: number,
  usedX: Set<string>,
): Signature<T> {
  const F = key.field;
  const indices = derivePositions(key.rootHint, message, key.params.K, key.params.T);
  let fresh = 0;
  const points: SignedPoint<T>[] = indices.map((i) => {
    const x = psi(F, i);
    const y = evalPoly(F, key.coeffs, x);
    if (!usedX.has(F.fmtFull(x))) fresh++;
    return { x, y, index: i };
  });
  return { message, signatureNumber, points, fresh };
}

/** The accumulating public record: OOD freebie plus every revealed pair. */
export class Ledger<T> {
  readonly signatures: Signature<T>[] = [];
  private readonly F: Field<T>;
  private readonly ood: Point<T>;

  constructor(key: JevilKey<T>) {
    this.F = key.field;
    this.ood = key.ood;
  }

  add(sig: Signature<T>): void {
    this.signatures.push(sig);
  }

  allPoints(): Point<T>[] {
    const pts: Point<T>[] = [this.ood];
    for (const s of this.signatures) pts.push(...s.points);
    return pts;
  }

  /** Distinct points (by x), OOD first. */
  ledgerPoints(): Point<T>[] {
    return dedupeByX(this.F, this.allPoints());
  }

  usedX(): Set<string> {
    const s = new Set<string>();
    for (const p of this.allPoints()) s.add(this.F.fmtFull(p.x));
    return s;
  }
}

export interface CliffStatus<T> {
  distinct: number;
  needed: number; // advertised D+1
  reached: boolean;
  recovered: T[] | null; // interpolated degree-D coefficients (live)
  exact: boolean; // recovered === true secret? (false for a malicious key)
}

/**
 * Evaluate the cliff against the current ledger. At the advertised D+1 distinct
 * points we interpolate a degree-D polynomial and VERIFY it equals the true
 * secret — proving the cliff is real. For a malicious (boosted-degree) key the
 * true secret is higher-degree, so this check fails: the cheater escaped.
 */
export function checkCliff<T>(key: JevilKey<T>, ledger: Ledger<T>): CliffStatus<T> {
  const F = key.field;
  const distinctPts = ledger.ledgerPoints();
  const distinct = distinctPts.length;
  const needed = key.params.D + 1;
  if (distinct < needed) {
    return { distinct, needed, reached: false, recovered: null, exact: false };
  }
  const recovered = interpolateCoeffs(F, distinctPts.slice(0, needed));
  const exact = coeffsEqual(F, recovered, key.coeffs);
  return { distinct, needed, reached: true, recovered, exact };
}

export interface DisjointResult {
  message: string;
  indices: number[];
  noncesTried: number;
}

/**
 * The grinding attack (paper §5.2): search nonced messages for one whose K
 * positions are ALL fresh, packing distinct evaluations into the public record
 * as fast as possible — K per signature — to reach the cliff in n*+1 signatures.
 */
export function findDisjointMessage<T>(
  key: JevilKey<T>,
  usedX: Set<string>,
  startNonce: number,
): DisjointResult {
  const F = key.field;
  const { K, T } = key.params;
  let nonce = startNonce;
  const maxTries = 100000;
  for (let t = 0; t < maxTries; t++, nonce++) {
    const message = `grind#${nonce}`;
    const indices = derivePositions(key.rootHint, message, K, T);
    if (indices.every((i) => !usedX.has(F.fmtFull(psi(F, i))))) {
      return { message, indices, noncesTried: t + 1 };
    }
  }
  throw new Error("findDisjointMessage: no fully-disjoint message found");
}
