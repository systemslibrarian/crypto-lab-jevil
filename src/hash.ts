// src/hash.ts — random-oracle stand-in over Web Crypto SHA-256.
//
// The Jevil paper uses SHAKE256 (the H_xof random oracle, Table 6). For the demo
// we instantiate the random oracle with SHA-256 via the platform Web Crypto API,
// which is a faithful random-oracle stand-in (noted in KNOWN-GAPS.md). All
// derivations below are domain-separated with the paper's tag names.

import { Q0, mod } from "./field";

// Paper tag names (Table 6), used for domain separation.
export const TAG_SEED = "JV-SEED"; // secret polynomial coefficients
export const TAG_OOD = "JV-OOD"; // out-of-domain freebie point
export const TAG_POSN = "JV-POSN"; // signature position indices

const enc = new TextEncoder();

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return new Uint8Array(digest);
}

/** Concatenate UTF-8 strings (joined by 0x1f unit separators) into bytes. */
function packInputs(parts: string[]): Uint8Array {
  return enc.encode(parts.join("\x1f"));
}

function bytesToBig(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  return acc;
}

/**
 * Domain-separated extendable-output function: hash `tag | inputs | counter`
 * and reduce each 256-bit block mod Q0, producing `count` field elements.
 */
export async function xof(
  tag: string,
  inputs: string[],
  count: number,
): Promise<bigint[]> {
  const out: bigint[] = [];
  for (let i = 0; i < count; i++) {
    const block = packInputs([tag, ...inputs, `#${i}`]);
    const digest = await sha256(block);
    out.push(mod(bytesToBig(digest)));
  }
  return out;
}

/** Derive the secret polynomial's M coefficients from the seed (Construction 1). */
export async function deriveCoeffs(seed: string, M: number): Promise<bigint[]> {
  return xof(TAG_SEED, [seed], M);
}

/** Derive the out-of-domain point z (Construction 1, step 4). */
export async function deriveOOD(rootHint: string): Promise<bigint> {
  const [z] = await xof(TAG_OOD, [rootHint], 1);
  return z;
}

/**
 * Derive K DISTINCT indices in {0..T−1}, sorted ascending (Construction 2,
 * step 2 — the HORS "Hash to Obtain Random Subset"). We pull field elements
 * from the XOF and reduce mod T, skipping collisions, until we have K of them.
 */
export async function derivePositions(
  rootHint: string,
  message: string,
  K: number,
  T: number,
): Promise<number[]> {
  if (K > T) throw new Error("derivePositions: K cannot exceed T");
  const Tb = BigInt(T);
  const chosen = new Set<number>();
  let draw = 0;
  while (chosen.size < K) {
    const block = await xof(TAG_POSN, [rootHint, message, `r${draw}`], 1);
    const idx = Number(mod(block[0]) % Tb);
    chosen.add(idx);
    draw++;
    if (draw > T * 64) throw new Error("derivePositions: exhausted draws");
  }
  return [...chosen].sort((a, b) => a - b);
}

export { Q0 };
