// Correctness test for the Jevil crypto core, over both fields.
// Run: npm test  (tsx scripts/core.test.ts)
import { GF, GF4, type Field } from "../src/ff";
import { interpolateCoeffs, coeffsEqual } from "../src/lagrange";
import {
  deriveParams,
  keyGen,
  evalPoly,
  psi,
  sign,
  Ledger,
  checkCliff,
  findDisjointMessage,
} from "../src/jevil";
import { deriveCoeffs } from "../src/hash";
import { Q0 } from "../src/field";

let failures = 0;
function check(name: string, cond: boolean) {
  console.log(`${cond ? "  ok  " : " FAIL "} ${name}`);
  if (!cond) failures++;
}

// ---- field axioms ----
function fieldAxioms<T>(F: Field<T>) {
  const xs = deriveCoeffs(F, "axiom-seed", 4);
  const [a, b, c] = xs;
  check(`${F.name}: a·1 = a`, F.eq(F.mul(a, F.one), a));
  check(`${F.name}: a·inv(a) = 1`, F.eq(F.mul(a, F.inv(a)), F.one));
  check(`${F.name}: a(b+c) = ab+ac`,
    F.eq(F.mul(a, F.add(b, c)), F.add(F.mul(a, b), F.mul(a, c))));
  check(`${F.name}: pow matches repeated mul`,
    F.eq(F.pow(a, 5n), F.mul(F.mul(F.mul(F.mul(a, a), a), a), a)));
}

// ---- interpolation recovers over a field ----
function interpRecovers<T>(F: Field<T>, D: number, seed: string) {
  const coeffs = deriveCoeffs(F, seed, D + 1);
  const pts = [];
  for (let i = 1; i <= D + 1; i++) {
    const x = psi(F, i);
    pts.push({ x, y: evalPoly(F, coeffs, x) });
  }
  check(`${F.name} D=${D}: D+1 points recover f`, coeffsEqual(F, interpolateCoeffs(F, pts), coeffs));
  check(`${F.name} D=${D}: D points do NOT recover f`,
    !coeffsEqual(F, interpolateCoeffs(F, pts.slice(0, D)), coeffs));
}

// ---- end-to-end grind to the cliff ----
function grindToCliff<T>(F: Field<T>, nStar: number, K: number, boost: number) {
  const key = keyGen(F, nStar, K, `e2e-${F.name}-${nStar}-${K}-${boost}`, boost);
  const ledger = new Ledger(key);
  let sigs = 0;
  while (!checkCliff(key, ledger).reached && sigs < nStar + 4) {
    const dr = findDisjointMessage(key, ledger.usedX(), sigs * 1000);
    ledger.add(sign(key, dr.message, ++sigs, ledger.usedX()));
  }
  const c = checkCliff(key, ledger);
  const tag = `${F.name} n*=${nStar},K=${K}${boost ? ` boost=${boost}` : ""}`;
  check(`${tag}: cliff fires at n*+1=${nStar + 1}`, sigs === nStar + 1 && c.reached);
  if (boost === 0) {
    check(`${tag}: recovered == true secret (EXACT)`, c.exact);
  } else {
    // A malicious higher-degree key escapes the ADVERTISED cliff…
    check(`${tag}: advertised cliff does NOT recover (escaped)`, c.reached && !c.exact);
    // …but with degree+boost+1 points the true key is still recoverable.
    while (ledger.ledgerPoints().length < key.params.D + 1 + boost) {
      const dr = findDisjointMessage(key, ledger.usedX(), sigs * 1000);
      ledger.add(sign(key, dr.message, ++sigs, ledger.usedX()));
    }
    const pts = ledger.ledgerPoints().slice(0, key.params.D + 1 + boost);
    check(`${tag}: true key recovers with D+1+boost points`,
      coeffsEqual(F, interpolateCoeffs(F, pts), key.coeffs));
  }
}

function main() {
  check("Q0 = 2^64 - 2^32 + 1", Q0 === (1n << 64n) - (1n << 32n) + 1n);
  check("psi(GF,0) = 1", GF.eq(psi(GF, 0), GF.one));

  fieldAxioms(GF);
  fieldAxioms(GF4);
  // GF4 specifics: u^4 = 7
  check("GF4: u^4 = 7", GF4.eq(GF4.pow([0n, 1n, 0n, 0n], 4n), [7n, 0n, 0n, 0n]));

  interpRecovers(GF, 3, "gf-3");
  interpRecovers(GF, 31, "gf-31"); // real smallest spec n*=1,K=16
  interpRecovers(GF4, 3, "gf4-3");
  interpRecovers(GF4, 31, "gf4-31");

  check("deriveParams n*=1,K=16: D=31", deriveParams(1, 16).D === 31);

  for (const [n, k] of [[1, 2], [3, 3], [2, 4]] as const) {
    grindToCliff(GF, n, k, 0);
    grindToCliff(GF4, n, k, 0);
  }
  // malicious mode over both fields
  grindToCliff(GF, 2, 3, 1);
  grindToCliff(GF4, 1, 2, 1);

  console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
