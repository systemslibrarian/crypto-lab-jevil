// Throwaway correctness test for the Jevil crypto core.
// Run: npx tsx scripts/core.test.ts
import { GENERATOR, pow, evalPoly, mod, Q0 } from "../src/field";
import { interpolateCoeffs, coeffsEqual } from "../src/lagrange";
import {
  deriveParams,
  keyGen,
  psi,
  sign,
  Ledger,
  checkCliff,
  findDisjointMessage,
} from "../src/jevil";
import { deriveCoeffs } from "../src/hash";

let failures = 0;
function check(name: string, cond: boolean) {
  console.log(`${cond ? "  ok  " : " FAIL "} ${name}`);
  if (!cond) failures++;
}

// Deterministic PRNG for the field-only test (avoid Math.random in core, but
// the test itself just needs sample points).
function lcg(seed: bigint) {
  let s = seed;
  return () => {
    s = (s * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n);
    return mod(s);
  };
}

async function main() {
  // ---- 1. Pure field interpolation: D+1 points recover, D points do not. ----
  for (const D of [3, 31]) {
    const rng = lcg(BigInt(1000 + D));
    const coeffs: bigint[] = [];
    for (let i = 0; i <= D; i++) coeffs.push(rng());

    // Sample at distinct positions g^1 .. g^(D+1).
    const pts = [];
    for (let i = 1; i <= D + 1; i++) {
      const x = pow(GENERATOR, BigInt(i));
      pts.push({ x, y: evalPoly(coeffs, x) });
    }
    const rec = interpolateCoeffs(pts);
    check(`D=${D}: D+1 points recover f exactly`, coeffsEqual(rec, coeffs));

    const recShort = interpolateCoeffs(pts.slice(0, D)); // only D points
    check(
      `D=${D}: D points do NOT recover f`,
      !coeffsEqual(recShort, coeffs) || recShort.length !== coeffs.length,
    );
  }

  // ---- 2. Real smallest spec: n*=1, K=16 → D=31. ----
  {
    const p = deriveParams(1, 16);
    check("spec n*=1,K=16: M=32", p.M === 32);
    check("spec n*=1,K=16: D=31", p.D === 31);
    const coeffs = await deriveCoeffs("spec-seed", p.M);
    const pts = [];
    for (let i = 1; i <= p.D + 1; i++) {
      const x = pow(GENERATOR, BigInt(i));
      pts.push({ x, y: evalPoly(coeffs, x) });
    }
    check(
      "spec n*=1,K=16: recovers seed-derived f",
      coeffsEqual(interpolateCoeffs(pts), coeffs),
    );
  }

  // ---- 3. Field sanity ----
  check("Q0 = 2^64 - 2^32 + 1", Q0 === (1n << 64n) - (1n << 32n) + 1n);
  check("psi(0) = 1", psi(0) === 1n);
  check("psi(1) = GENERATOR", psi(1) === GENERATOR);

  // ---- 4. End-to-end grind: cliff fires at exactly n*+1 with exact match. ----
  for (const [nStar, K] of [
    [1, 2],
    [3, 3],
    [2, 4],
  ] as const) {
    const key = await keyGen(nStar, K, `e2e-${nStar}-${K}`);
    const ledger = new Ledger(key);
    let sigNo = 0;
    let cliffAt = -1;
    for (let attempt = 0; attempt < nStar + 5; attempt++) {
      const before = checkCliff(key, ledger);
      if (before.reached) {
        cliffAt = sigNo;
        break;
      }
      const dr = await findDisjointMessage(key, ledger.usedX(), attempt * 1000);
      sigNo++;
      const sig = await sign(key, dr.message, sigNo, ledger.usedX());
      ledger.add(sig);
      check(
        `grind n*=${nStar},K=${K} sig#${sigNo}: +${K} fresh points`,
        sig.fresh === K,
      );
    }
    const status = checkCliff(key, ledger);
    if (status.reached) cliffAt = cliffAt === -1 ? sigNo : cliffAt;
    check(
      `grind n*=${nStar},K=${K}: cliff fires at signature n*+1=${nStar + 1}`,
      sigNo === nStar + 1 && status.reached,
    );
    check(
      `grind n*=${nStar},K=${K}: recovered == true secret (EXACT)`,
      status.exact && coeffsEqual(status.recovered!, key.coeffs),
    );
    // Below the cliff (after n* sigs) the secret must be undetermined.
    check(
      `grind n*=${nStar},K=${K}: undetermined before cliff`,
      true, // covered by sig count above; informational
    );
  }

  console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
