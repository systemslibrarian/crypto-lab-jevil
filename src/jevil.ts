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

import { GF, GF4, type Field } from "./ff";
import { deriveCoeffs, deriveOOD, derivePositions, hashId, commit } from "./hash";
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
  fingerprint: string; // public binding hash commitment to coeffs
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

/**
 * Bytes of entropy in a freshly generated seed.
 *
 * 32, not 8. An 8-byte seed made the demo's ENTIRE key space 2^64 — enumerable,
 * and directly at odds with the "~124-bit" language the page uses elsewhere.
 * Because the coefficients are derived deterministically from the seed and the
 * public key publishes a binding fingerprint of them, the seed space IS the
 * search space for an unbounded adversary. The paper's secret key is 32 bytes;
 * this now matches it.
 */
export const SEED_BYTES = 32;

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

/** The canonical string forms of every position psi(0)…psi(T−1). */
export function positionDomain<T>(F: Field<T>, T_: number): Set<string> {
  const s = new Set<string>();
  for (let i = 0; i < T_; i++) s.add(F.fmtFull(psi(F, i)));
  return s;
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
  // The OOD point must actually be out of the position domain, or it would be
  // deduped against a signed point and the cliff would need one more signature
  // than the key advertises. Enforced, not merely improbable.
  const z = deriveOOD(F, rootHint, positionDomain(F, params.T));
  const w = evalPoly(F, coeffs, z); // f(z) — the freebie head start
  const fingerprint = commit(F, coeffs); // public binding commitment to the key
  return {
    params,
    field: F,
    seed,
    coeffs,
    degreeBoost,
    rootHint,
    fingerprint,
    ood: { x: z, y: w },
  };
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

// ------------------------------------------------- auditable transcript ----
// The transcript carries ONLY public data — params, the field id, the OOD
// freebie, the binding key fingerprint, and the distinct revealed points. The
// secret coefficients are NOT included. An independent verifier (verify.ts /
// `npm run verify`) can reconstruct the key from this alone and check it against
// the fingerprint — proving recovery comes from public data, not a stored secret.

export interface Transcript {
  scheme: "crypto-lab-jevil";
  version: 1;
  field: "base" | "tower";
  params: Params;
  rootHint: string;
  fingerprint: string;
  ood: { x: string[]; y: string[] };
  points: { x: string[]; y: string[] }[];
}

export function exportTranscript<T>(key: JevilKey<T>, ledger: Ledger<T>): Transcript {
  const F = key.field;
  return {
    scheme: "crypto-lab-jevil",
    version: 1,
    field: F.id,
    params: key.params,
    rootHint: key.rootHint,
    fingerprint: key.fingerprint,
    ood: { x: F.serialize(key.ood.x), y: F.serialize(key.ood.y) },
    points: ledger.ledgerPoints().map((p) => ({
      x: F.serialize(p.x),
      y: F.serialize(p.y),
    })),
  };
}

export type VerifyCode =
  | "OK_INTERNALLY_CONSISTENT"
  | "OK_ANCHORED"
  | "BAD_SCHEMA"
  | "BAD_VERSION"
  | "BAD_FIELD"
  | "BAD_PARAMS"
  | "BAD_POINTS"
  | "BAD_OOD"
  | "INSUFFICIENT_POINTS"
  | "FINGERPRINT_MISMATCH"
  | "ANCHOR_MISMATCH";

export interface VerifyResult {
  ok: boolean;
  /**
   * True only when the caller supplied an expected fingerprint from an
   * independent source AND the recovered key matched it. `ok` without this means
   * "these points interpolate to a polynomial whose hash equals the hash stored
   * in this same file" — internal consistency, which a forger can also produce.
   */
  anchored: boolean;
  code: VerifyCode;
  reason: string;
  recoveredFingerprint: string | null;
  distinct: number;
  needed: number;
}

const SUPPORTED_VERSION = 1;
const MAX_POINTS = 4096; // a transcript is small; refuse a resource-exhaustion file

function fail(code: VerifyCode, reason: string, distinct = 0, needed = 0): VerifyResult {
  return { ok: false, anchored: false, code, reason, recoveredFingerprint: null, distinct, needed };
}

/**
 * Independently verify a transcript using only its public data.
 *
 * TWO DIFFERENT CLAIMS, which this used to collapse into one "VERIFIED":
 *
 *   internally consistent — the supplied points interpolate to a polynomial
 *     whose hash equals the fingerprint SUPPLIED IN THE SAME FILE. Anyone can
 *     manufacture this: generate any key, export its transcript, and it passes.
 *     Measured: a transcript exported from a completely different key verifies.
 *
 *   anchored — the recovered key also matches an `expectedFingerprint` the
 *     caller obtained from somewhere other than this file. Only this shows the
 *     transcript belongs to a particular advertised public key.
 *
 * Every self-describing field is now checked. Previously 10 of 11 tampered
 * fields still verified: `ood`, `version`, `field`, `rootHint`, `nStar`, `M`,
 * `T`, `nCliff` and duplicated points were all ignored, and an unknown `field`
 * silently fell through to the base field.
 */
export function verifyTranscript(t: Transcript, expectedFingerprint?: string): VerifyResult {
  if (!t || typeof t !== "object") return fail("BAD_SCHEMA", "transcript is not an object");
  if (t.scheme !== "crypto-lab-jevil") return fail("BAD_SCHEMA", "not a crypto-lab-jevil transcript");
  if (t.version !== SUPPORTED_VERSION) {
    return fail("BAD_VERSION", `unsupported transcript version ${t.version} (this verifier speaks ${SUPPORTED_VERSION})`);
  }
  if (t.field !== "base" && t.field !== "tower") {
    return fail("BAD_FIELD", `unknown field "${t.field}" — refusing to guess (it used to fall through to the base field)`);
  }
  if (typeof t.fingerprint !== "string" || !/^[0-9a-f]{64}$/.test(t.fingerprint)) {
    return fail("BAD_SCHEMA", "fingerprint must be 64 lowercase hex characters");
  }
  if (typeof t.rootHint !== "string" || !/^jv-[0-9a-f]{12}$/.test(t.rootHint)) {
    return fail("BAD_SCHEMA", `rootHint must look like jv-<12 hex>, got "${t.rootHint}"`);
  }

  // Parameter identities (paper §4.1). A transcript whose params contradict each
  // other cannot describe any real key, whatever its points interpolate to.
  const p = t.params;
  const ints = (["nStar", "K", "M", "D", "T", "nCliff"] as const).every(
    (k) => Number.isInteger(p?.[k]) && p[k] >= 0 && p[k] <= 100000,
  );
  if (!ints) return fail("BAD_PARAMS", "params must be small non-negative integers");
  if (p.nStar < 1 || p.K < 1) return fail("BAD_PARAMS", "n* and K must be at least 1");
  if (p.M !== (p.nStar + 1) * p.K) return fail("BAD_PARAMS", `M must equal (n*+1)·K = ${(p.nStar + 1) * p.K}, got ${p.M}`);
  if (p.D !== p.M - 1) return fail("BAD_PARAMS", `D must equal M−1 = ${p.M - 1}, got ${p.D}`);
  if (p.T !== 2 * p.M) return fail("BAD_PARAMS", `T must equal 2M = ${2 * p.M}, got ${p.T}`);
  if (p.nCliff !== p.nStar + 1) return fail("BAD_PARAMS", `nCliff must equal n*+1 = ${p.nStar + 1}, got ${p.nCliff}`);

  const F: Field<any> = t.field === "tower" ? GF4 : GF;
  const needed = p.D + 1;

  if (!Array.isArray(t.points)) return fail("BAD_POINTS", "points must be an array");
  if (t.points.length > MAX_POINTS) {
    return fail("BAD_POINTS", `${t.points.length} points exceeds the ${MAX_POINTS} cap`);
  }
  const coordOk = (w: unknown): boolean =>
    Array.isArray(w) && w.length === F.coords && w.every((c) => typeof c === "string" && /^\d+$/.test(c));
  for (const [i, pt] of t.points.entries()) {
    if (!coordOk(pt?.x) || !coordOk(pt?.y)) {
      return fail("BAD_POINTS", `point ${i} does not have ${F.coords} decimal coordinate(s) for the ${t.field} field`);
    }
  }
  if (!coordOk(t.ood?.x) || !coordOk(t.ood?.y)) {
    return fail("BAD_OOD", `ood does not have ${F.coords} decimal coordinate(s) for the ${t.field} field`);
  }

  const pts: Point<any>[] = t.points.map((q) => ({ x: F.deserialize(q.x), y: F.deserialize(q.y) }));

  // The file must not carry two different y for one x, and must not pad itself
  // with duplicates to look larger than it is.
  const byX = new Map<string, string>();
  for (const q of pts) {
    const kx = F.fmtFull(q.x);
    const ky = F.fmtFull(q.y);
    const prev = byX.get(kx);
    if (prev !== undefined) {
      return fail(
        "BAD_POINTS",
        prev === ky ? `duplicate point at x=${kx}` : `contradictory y values at x=${kx}`,
      );
    }
    byX.set(kx, ky);
  }

  // The separate `ood` field used to be decorative — altering it changed nothing,
  // because ledgerPoints() already puts the OOD pair first in `points`. It must
  // be the same pair the interpolation actually consumes.
  const oodX = F.deserialize(t.ood.x);
  const oodY = F.deserialize(t.ood.y);
  const listedOodY = byX.get(F.fmtFull(oodX));
  if (listedOodY === undefined) {
    return fail("BAD_OOD", "the ood point is not among the transcript's points");
  }
  if (listedOodY !== F.fmtFull(oodY)) {
    return fail("BAD_OOD", "the ood y value disagrees with the same x in points");
  }
  // rootHint is not decorative either: z is deriveOOD(rootHint), so the pair
  // (rootHint, ood.x) is checkable from public data alone. Without this, the
  // rootHint could be swapped for any other key's and the file still verified.
  if (!F.eq(oodX, deriveOOD(F, t.rootHint, positionDomain(F, p.T)))) {
    return fail("BAD_OOD", "the ood point is not the one this rootHint derives — rootHint and ood disagree");
  }

  const distinct = dedupeByX(F, pts);
  if (distinct.length < needed) {
    return {
      ok: false, anchored: false, code: "INSUFFICIENT_POINTS",
      reason: `insufficient points: ${distinct.length} distinct of ${needed} needed`,
      recoveredFingerprint: null, distinct: distinct.length, needed,
    };
  }

  const recovered = interpolateCoeffs(F, distinct.slice(0, needed));
  const recoveredFingerprint = commit(F, recovered);
  if (recoveredFingerprint !== t.fingerprint) {
    return {
      ok: false, anchored: false, code: "FINGERPRINT_MISMATCH",
      reason: "recovered degree-D key does NOT match the fingerprint in this file (over-degree / malicious key, or tampered transcript)",
      recoveredFingerprint, distinct: distinct.length, needed,
    };
  }

  if (expectedFingerprint !== undefined) {
    if (recoveredFingerprint !== expectedFingerprint) {
      return {
        ok: false, anchored: false, code: "ANCHOR_MISMATCH",
        reason: "the recovered key does not match the expected fingerprint you supplied — this transcript belongs to a different key",
        recoveredFingerprint, distinct: distinct.length, needed,
      };
    }
    return {
      ok: true, anchored: true, code: "OK_ANCHORED",
      reason: "recovered key matches the expected fingerprint supplied independently of this file",
      recoveredFingerprint, distinct: distinct.length, needed,
    };
  }

  return {
    ok: true, anchored: false, code: "OK_INTERNALLY_CONSISTENT",
    reason: "internally consistent: these points interpolate to a key whose hash equals the fingerprint stored in this same file (supply an expected fingerprint to anchor it to a known public key)",
    recoveredFingerprint, distinct: distinct.length, needed,
  };
}
