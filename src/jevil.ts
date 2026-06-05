// src/jevil.ts — the Jevil few-time signature scheme (demo realization).
//
// Sources: Kobeissi, "Jevil", Cryptology ePrint 2026/1103. Construction 1
// (KeyGen + OOD freebie), Construction 2 (HORS position derivation), §4.1
// (parameters), §5.2–5.3 (the disjoint-position grind), Theorem 1/2 (the cliff).
//
// The secret key IS the coefficient vector of a degree-D polynomial f. Each
// signature reveals K evaluations f(x_t) at hash-derived positions x_t = g^{i_t}.
// The public key ships one free out-of-domain pair (z, f(z)). Once the DISTINCT
// revealed points (including the OOD freebie) reach D+1, anyone can Lagrange-
// interpolate f exactly — the cliff. This module makes that fact executable.

import { GENERATOR, pow, evalPoly, mod } from "./field";
import { deriveCoeffs, deriveOOD, derivePositions } from "./hash";
import {
  interpolateCoeffs,
  dedupeByX,
  coeffsEqual,
  type Point,
} from "./lagrange";

export interface Params {
  nStar: number; // signing budget chosen at KeyGen
  K: number; // positions revealed per signature
  M: number; // number of secret coefficients = (n*+1)·K
  D: number; // polynomial degree = M − 1
  T: number; // position domain size {0..T−1}
  nCliff: number; // signature at which the cliff fires = n*+1
}

export interface JevilKey {
  params: Params;
  seed: string; // secret seed (would never be exposed in reality)
  coeffs: bigint[]; // THE SECRET: degree-D polynomial coefficients
  rootHint: string; // public per-key identifier
  ood: Point; // public out-of-domain freebie (z, f(z))
}

export interface SignedPoint extends Point {
  index: number; // the position index i_t (x = g^{i_t})
}

export interface Signature {
  message: string;
  signatureNumber: number; // 1-based
  points: SignedPoint[];
  fresh: number; // how many of these x were new to the ledger when signed
}

/** Derive scheme parameters (paper §4.1). */
export function deriveParams(nStar: number, K: number): Params {
  const M = (nStar + 1) * K;
  const D = M - 1;
  // Domain comfortably larger than M so the grind has room to find disjoint
  // sets, while honest signing still sometimes collides (duplicates that do not
  // advance the cliff). Real parameters use a far larger T.
  const T = 2 * M;
  return { nStar, K, M, D, T, nCliff: nStar + 1 };
}

/** Position-to-field map psi(i) = g^i (paper Construction 2). */
export function psi(i: number): bigint {
  return pow(GENERATOR, BigInt(i));
}

/** KeyGen (paper Construction 1): secret polynomial + public OOD freebie. */
export async function keyGen(
  nStar: number,
  K: number,
  seed: string,
): Promise<JevilKey> {
  const params = deriveParams(nStar, K);
  const coeffs = await deriveCoeffs(seed, params.M); // SECRET
  // Public per-key root hint (a demo stand-in for the commitment root).
  const rootHint = "jv-" + (await hashId(seed));
  const z = await deriveOOD(rootHint);
  const w = evalPoly(coeffs, z); // f(z) — the freebie head start
  return { params, seed, coeffs, rootHint, ood: { x: z, y: w } };
}

async function hashId(seed: string): Promise<string> {
  const bytes = new TextEncoder().encode("JV-ROOT\x1f" + seed);
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", bytes as BufferSource),
  );
  return Array.from(digest.slice(0, 6))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Sign honestly: positions are whatever the message hashes to. */
export async function sign(
  key: JevilKey,
  message: string,
  signatureNumber: number,
  usedX: Set<string>,
): Promise<Signature> {
  const indices = await derivePositions(
    key.rootHint,
    message,
    key.params.K,
    key.params.T,
  );
  let fresh = 0;
  const points: SignedPoint[] = indices.map((i) => {
    const x = psi(i);
    const y = evalPoly(key.coeffs, x);
    if (!usedX.has(x.toString())) fresh++;
    return { x, y, index: i };
  });
  return { message, signatureNumber, points, fresh };
}

/**
 * The accumulating public record an observer sees: the OOD freebie plus every
 * revealed signature pair. ledgerPoints() returns DISTINCT pairs (by x) — only
 * distinct positions advance the cliff (paper §5.2–5.3).
 */
export class Ledger {
  readonly signatures: Signature[] = [];
  private readonly ood: Point;

  constructor(key: JevilKey) {
    this.ood = key.ood;
  }

  add(sig: Signature): void {
    this.signatures.push(sig);
  }

  /** All points including duplicates and the OOD freebie. */
  allPoints(): Point[] {
    const pts: Point[] = [this.ood];
    for (const s of this.signatures) pts.push(...s.points);
    return pts;
  }

  /** Distinct points (by x), OOD first. */
  ledgerPoints(): Point[] {
    return dedupeByX(this.allPoints());
  }

  /** Set of x-coordinates seen so far (for freshness checks). */
  usedX(): Set<string> {
    const s = new Set<string>();
    for (const p of this.allPoints()) s.add(p.x.toString());
    return s;
  }
}

export interface CliffStatus {
  distinct: number; // distinct points accumulated
  needed: number; // D+1
  reached: boolean;
  recovered: bigint[] | null; // interpolated coefficients (live), or null
  exact: boolean; // recovered === true secret?
}

/**
 * Evaluate the cliff against the current ledger. When distinct ≥ D+1 we
 * interpolate the polynomial from the first D+1 distinct points and VERIFY the
 * recovered coefficients equal the true secret — proving the cliff is real, not
 * a scripted reveal.
 */
export function checkCliff(key: JevilKey, ledger: Ledger): CliffStatus {
  const distinctPts = ledger.ledgerPoints();
  const distinct = distinctPts.length;
  const needed = key.params.D + 1;
  if (distinct < needed) {
    return { distinct, needed, reached: false, recovered: null, exact: false };
  }
  const recovered = interpolateCoeffs(distinctPts.slice(0, needed));
  const exact = coeffsEqual(recovered, key.coeffs);
  return { distinct, needed, reached: true, recovered, exact };
}

export interface DisjointResult {
  message: string;
  indices: number[];
  noncesTried: number;
}

/**
 * The grinding attack (paper §5.2): search nonced messages for one whose K
 * positions are ALL fresh (disjoint from the ledger), packing distinct
 * evaluations into the public record as fast as possible — K per signature —
 * so the cliff is reached in exactly ceil(M/K) = n*+1 signatures.
 */
export async function findDisjointMessage(
  key: JevilKey,
  usedX: Set<string>,
  startNonce: number,
): Promise<DisjointResult> {
  const { K, T } = key.params;
  let nonce = startNonce;
  const maxTries = 100000;
  for (let t = 0; t < maxTries; t++, nonce++) {
    const message = `grind#${nonce}`;
    const indices = await derivePositions(key.rootHint, message, K, T);
    const allFresh = indices.every((i) => !usedX.has(psi(i).toString()));
    if (allFresh) {
      return { message, indices, noncesTried: t + 1 };
    }
  }
  // Fallback: return whatever maximizes fresh count (rare with comfortable T).
  throw new Error("findDisjointMessage: no fully-disjoint message found");
}

export { mod };
