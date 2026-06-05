// src/ff.ts — pluggable finite fields.
//
// The cliff math is identical over any field, so the scheme (jevil.ts) and the
// interpolation (lagrange.ts) are written generically over a `Field<T>`. Two
// implementations are provided:
//
//   GF  — the Goldilocks base field F_{q0}  (T = bigint), legible 64-bit numbers.
//   GF4 — its degree-4 tower F_{q0^4} ≈ 2^256 (T = bigint[4]), the field the
//         paper actually uses (§3.3). Less legible, but exactly faithful.
//
// The demo defaults to GF for readability and offers GF4 as a fidelity toggle.

import * as B from "./field";

export interface Field<T> {
  readonly id: "base" | "tower";
  readonly name: string;
  /** base-field words consumed per element when sampling from the XOF */
  readonly coords: number;
  readonly zero: T;
  readonly one: T;
  /** generator used for the position map psi(i) = generator^i */
  readonly generator: T;
  add(a: T, b: T): T;
  sub(a: T, b: T): T;
  mul(a: T, b: T): T;
  pow(a: T, e: bigint): T;
  inv(a: T): T;
  eq(a: T, b: T): boolean;
  /** build an element from `coords` base-field words (e.g. XOF output) */
  fromWords(words: bigint[]): T;
  /** canonical decimal-string coords, for transcript export */
  serialize(a: T): string[];
  /** inverse of serialize, for transcript import */
  deserialize(words: string[]): T;
  fmt(a: T): string;
  fmtFull(a: T): string;
}

// --------------------------------------------------- base field F_{q0} ------
export const GF: Field<bigint> = {
  id: "base",
  name: "Goldilocks F_q₀",
  coords: 1,
  zero: 0n,
  one: 1n,
  generator: B.GENERATOR,
  add: B.add,
  sub: B.sub,
  mul: B.mul,
  pow: B.pow,
  inv: B.inv,
  eq: (a, b) => B.mod(a) === B.mod(b),
  fromWords: (w) => B.mod(w[0]),
  serialize: (a) => [B.mod(a).toString()],
  deserialize: (w) => B.mod(BigInt(w[0])),
  fmt: B.fmt,
  fmtFull: B.fmtFull,
};

// --------------------------------------- quartic tower F_{q0^4}, u^4 = 7 ----
// Elements are [a0,a1,a2,a3] meaning a0 + a1·u + a2·u² + a3·u³ with u⁴ = 7.
// X⁴ − 7 is irreducible over Goldilocks (the Plonky2 quartic extension).
const W = 7n;
const ORDER4 = B.Q0 ** 4n;
const INV_EXP4 = ORDER4 - 2n; // a^(q⁴−2) = a⁻¹ for nonzero a

type E4 = bigint[];

function gf4mul(a: E4, b: E4): E4 {
  const c = [0n, 0n, 0n, 0n, 0n, 0n, 0n];
  for (let i = 0; i < 4; i++) {
    for (let j = 0; j < 4; j++) {
      c[i + j] = B.add(c[i + j], B.mul(a[i], b[j]));
    }
  }
  // reduce u⁴=W, u⁵=W·u, u⁶=W·u²
  return [
    B.add(c[0], B.mul(W, c[4])),
    B.add(c[1], B.mul(W, c[5])),
    B.add(c[2], B.mul(W, c[6])),
    c[3],
  ];
}

function gf4pow(a: E4, e: bigint): E4 {
  let base = a.slice();
  let result: E4 = [1n, 0n, 0n, 0n];
  let exp = e;
  while (exp > 0n) {
    if (exp & 1n) result = gf4mul(result, base);
    base = gf4mul(base, base);
    exp >>= 1n;
  }
  return result;
}

export const GF4: Field<E4> = {
  id: "tower",
  name: "Tower F_{q₀⁴} ≈ 2²⁵⁶",
  coords: 4,
  zero: [0n, 0n, 0n, 0n],
  one: [1n, 0n, 0n, 0n],
  generator: [B.GENERATOR, 0n, 0n, 0n], // base generator, embedded
  add: (a, b) => [
    B.add(a[0], b[0]),
    B.add(a[1], b[1]),
    B.add(a[2], b[2]),
    B.add(a[3], b[3]),
  ],
  sub: (a, b) => [
    B.sub(a[0], b[0]),
    B.sub(a[1], b[1]),
    B.sub(a[2], b[2]),
    B.sub(a[3], b[3]),
  ],
  mul: gf4mul,
  pow: gf4pow,
  inv: (a) => {
    if (a.every((x) => B.mod(x) === 0n)) throw new Error("GF4: inverse of zero");
    return gf4pow(a, INV_EXP4);
  },
  eq: (a, b) =>
    B.mod(a[0]) === B.mod(b[0]) &&
    B.mod(a[1]) === B.mod(b[1]) &&
    B.mod(a[2]) === B.mod(b[2]) &&
    B.mod(a[3]) === B.mod(b[3]),
  fromWords: (w) => [B.mod(w[0]), B.mod(w[1]), B.mod(w[2]), B.mod(w[3])],
  serialize: (a) => a.map((x) => B.mod(x).toString()),
  deserialize: (w) => [B.mod(BigInt(w[0])), B.mod(BigInt(w[1])), B.mod(BigInt(w[2])), B.mod(BigInt(w[3]))],
  fmt: (a) =>
    a.every((x, i) => i === 0 || B.mod(x) === 0n)
      ? B.fmt(a[0]) // pure base element — show compactly
      : "⟨" + a.map(B.fmt).join(", ") + "⟩",
  fmtFull: (a) => "⟨" + a.map(B.fmtFull).join(", ") + "⟩",
};
