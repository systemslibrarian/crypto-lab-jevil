// src/hash.ts — random oracle via SHAKE256 (the paper's H_xof, Table 6).
//
// SHAKE256 is an extendable-output function, so we hash `tag | inputs` once and
// squeeze as many bytes as we need. All derivations are domain-separated with
// the paper's tag names. Field elements are built from the squeezed bytes via
// the active Field's `fromWords`, so this layer works over the base field or the
// quartic tower unchanged.

import { shake256 } from "@noble/hashes/sha3.js";
import { Q0, mod } from "./field";
import type { Field } from "./ff";

// Paper tag names (Table 6), used for domain separation.
export const TAG_SEED = "JV-SEED"; // secret polynomial coefficients
export const TAG_OOD = "JV-OOD"; // out-of-domain freebie point
export const TAG_POSN = "JV-POSN"; // signature position indices
export const TAG_ROOT = "JV-ROOT"; // public per-key root hint
export const TAG_COMMIT = "JV-COMMIT"; // binding hash commitment to the key

const enc = new TextEncoder();

// 16 bytes (128 bits) reduced mod q0 (~64 bits) keeps the modular bias negligible.
const BYTES_PER_WORD = 16;

function packInputs(parts: string[]): Uint8Array {
  return enc.encode(parts.join("\x1f"));
}

/**
 * Domain-separated XOF: squeeze `count` base-field words from
 * SHAKE256(tag | inputs), each a 128-bit chunk reduced mod q0.
 */
export function xof(tag: string, inputs: string[], count: number): bigint[] {
  const out = shake256(packInputs([tag, ...inputs]), {
    dkLen: count * BYTES_PER_WORD,
  });
  const words: bigint[] = [];
  for (let i = 0; i < count; i++) {
    let acc = 0n;
    for (let j = 0; j < BYTES_PER_WORD; j++) {
      acc = (acc << 8n) | BigInt(out[i * BYTES_PER_WORD + j]);
    }
    words.push(mod(acc));
  }
  return words;
}

/** A short public hex id derived from the seed (the demo's root hint). */
export function hashId(seed: string): string {
  const out = shake256(packInputs([TAG_ROOT, seed]), { dkLen: 6 });
  return Array.from(out)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * A binding hash commitment to a coefficient vector: SHAKE256 over the
 * serialized coefficients. This is a real *binding* commitment (it pins down the
 * exact vector), published in the public key so an external verifier can confirm
 * a recovered key matches. It is NOT the paper's zk-WHIR commitment, which also
 * binds *evaluations* succinctly and in zero knowledge — see KNOWN-GAPS.md.
 */
export function commit<T>(F: Field<T>, coeffs: T[]): string {
  const parts = coeffs.flatMap((c) => F.serialize(c));
  const out = shake256(packInputs([TAG_COMMIT, String(coeffs.length), ...parts]), {
    dkLen: 32,
  });
  return Array.from(out)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Derive the secret polynomial's M coefficients from the seed (Construction 1). */
export function deriveCoeffs<T>(F: Field<T>, seed: string, M: number): T[] {
  const words = xof(TAG_SEED, [seed], M * F.coords);
  const coeffs: T[] = [];
  for (let i = 0; i < M; i++) {
    coeffs.push(F.fromWords(words.slice(i * F.coords, (i + 1) * F.coords)));
  }
  return coeffs;
}

/** Derive the out-of-domain point z (Construction 1, step 4). */
export function deriveOOD<T>(F: Field<T>, rootHint: string): T {
  return F.fromWords(xof(TAG_OOD, [rootHint], F.coords));
}

/**
 * Derive K DISTINCT indices in {0..T−1}, sorted ascending (Construction 2,
 * step 2 — the HORS "Hash to Obtain Random Subset").
 */
export function derivePositions(
  rootHint: string,
  message: string,
  K: number,
  T: number,
): number[] {
  if (K > T) throw new Error("derivePositions: K cannot exceed T");
  const Tb = BigInt(T);
  const chosen = new Set<number>();
  let draw = 0;
  while (chosen.size < K) {
    const [word] = xof(TAG_POSN, [rootHint, message, `r${draw}`], 1);
    chosen.add(Number(mod(word) % Tb));
    draw++;
    if (draw > T * 64) throw new Error("derivePositions: exhausted draws");
  }
  return [...chosen].sort((a, b) => a - b);
}

export { Q0 };
