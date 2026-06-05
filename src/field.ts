// src/field.ts — Goldilocks base field arithmetic.
//
// The Jevil paper (§3.3) works over the Goldilocks prime q0 = 2^64 − 2^32 + 1,
// then builds a degree-4 tower F_{q0^4} ≈ 2^256. For this demo we use the base
// field directly so the cliff stays exact and the numbers stay legible. The
// arithmetic here is faithful finite-field arithmetic over q0 — every operation
// is a real BigInt computation, nothing is faked.

// q0 = 2^64 − 2^32 + 1 — the exact Goldilocks base field from paper §3.3.
export const Q0 = (1n << 64n) - (1n << 32n) + 1n;

// Generator of the multiplicative group, used for the position map psi(i) = g^i.
// 7 is a generator of F_{q0}^* (a known primitive root for Goldilocks).
export const GENERATOR = 7n;

/** Reduce x into the canonical range [0, Q0). Handles negative inputs. */
export function mod(x: bigint): bigint {
  const r = x % Q0;
  return r < 0n ? r + Q0 : r;
}

export function add(a: bigint, b: bigint): bigint {
  return mod(a + b);
}

export function sub(a: bigint, b: bigint): bigint {
  return mod(a - b);
}

export function mul(a: bigint, b: bigint): bigint {
  return mod(a * b);
}

/** Modular exponentiation by square-and-multiply. */
export function pow(base: bigint, exp: bigint): bigint {
  let b = mod(base);
  let e = exp;
  let result = 1n;
  while (e > 0n) {
    if (e & 1n) result = mul(result, b);
    b = mul(b, b);
    e >>= 1n;
  }
  return result;
}

/** Multiplicative inverse via Fermat's little theorem: a^(Q0−2) mod Q0. */
export function inv(a: bigint): bigint {
  const am = mod(a);
  if (am === 0n) throw new Error("field: inverse of zero");
  return pow(am, Q0 - 2n);
}

export function div(a: bigint, b: bigint): bigint {
  return mul(a, inv(b));
}

/**
 * Evaluate a polynomial at x via Horner's method.
 * Coefficients are low-order first: coeffs[0] + coeffs[1]·x + coeffs[2]·x² + …
 */
export function evalPoly(coeffs: bigint[], x: bigint): bigint {
  let acc = 0n;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    acc = add(mul(acc, x), coeffs[i]);
  }
  return acc;
}

/** Abbreviate a big field element for display: 0x1a2b…9f3c. */
export function fmt(x: bigint): string {
  const hex = mod(x).toString(16);
  if (hex.length <= 10) return "0x" + hex;
  return "0x" + hex.slice(0, 6) + "…" + hex.slice(-4);
}

/** Full hex (no abbreviation) for side-by-side comparisons. */
export function fmtFull(x: bigint): string {
  return "0x" + mod(x).toString(16).padStart(16, "0");
}
