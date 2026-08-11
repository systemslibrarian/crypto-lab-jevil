// Correctness test for the Jevil crypto core, over both fields.
// Run: npm test  (tsx scripts/core.test.ts)
import { GF, GF4, type Field } from "../src/ff";
import { interpolateCoeffs, coeffsEqual, candidateCount, formatCount } from "../src/lagrange";
import {
  deriveParams,
  keyGen,
  evalPoly,
  psi,
  positionDomain,
  sign,
  Ledger,
  checkCliff,
  findDisjointMessage,
  exportTranscript,
  verifyTranscript,
  SEED_BYTES,
  type Transcript,
} from "../src/jevil";
import { deriveCoeffs, deriveOOD, commit } from "../src/hash";
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

// ---- claims the page renders about what is hidden ----
//
// The page used to say "infinitely many degree-D polynomials fit" and "even
// unlimited computing power can't tell which is f". The first is false in a
// finite field; the second is false for THIS implementation, whose public key
// includes a binding fingerprint of the coefficients.
function hiddenClaims() {
  const p = deriveParams(3, 3); // D = 11
  check(
    "candidateCount: 0 revealed points over the base field = q0^(D+1)",
    candidateCount(GF, p.D, 0) === Q0 ** BigInt(p.D + 1),
  );
  check(
    "candidateCount: strictly decreases with each distinct point",
    (() => {
      let prev = candidateCount(GF, p.D, 0);
      let steps = 0;
      for (let m = 1; m <= p.D + 1; m++) {
        const cur = candidateCount(GF, p.D, m);
        if (cur >= prev) return false;
        prev = cur;
        steps++;
      }
      return steps === p.D + 1; // the sweep must actually have run
    })(),
  );
  check(
    "candidateCount: collapses to exactly 1 at D+1 (and stays 1 beyond)",
    candidateCount(GF, p.D, p.D + 1) === 1n && candidateCount(GF, p.D, p.D + 5) === 1n,
  );
  check(
    "candidateCount: the tower field's count is larger at the same point count",
    candidateCount(GF4, p.D, 3) > candidateCount(GF, p.D, 3),
  );
  check(
    "candidateCount is FINITE — 'infinitely many' is false in a finite field",
    candidateCount(GF, p.D, 1) === Q0 ** 11n && candidateCount(GF, p.D, 1) < 2n ** 1024n,
  );
  check("formatCount renders a power of two", formatCount(2n ** 127n) === "2^127");

  // An unbounded adversary CAN pick f out using only the published fingerprint —
  // no signatures, no revealed points. Run at a seed size small enough to
  // execute here; the shipped seed space is merely larger.
  const space = 4096;
  const target = keyGen(GF, 1, 2, (1234).toString(16).padStart(4, "0"));
  let found = -1;
  let tried = 0;
  for (let v = 0; v < space; v++) {
    tried++;
    if (commit(GF, keyGen(GF, 1, 2, v.toString(16).padStart(4, "0")).coeffs) === target.fingerprint) {
      found = v;
      break;
    }
  }
  check(
    "the published fingerprint alone identifies f under exhaustive search " +
      `(recovered seed ${found} after ${tried} candidates, zero signatures)`,
    found === 1234,
  );
  check("…and the search really ran (not short-circuited)", tried > 1);

  // The seed must have paper-scale entropy, or that search is cheap in practice.
  check(
    `randomSeed emits ${SEED_BYTES} bytes; 8 bytes made the whole key space 2^64`,
    SEED_BYTES === 32,
  );
  check(
    "a seed of SEED_BYTES renders as 64 hex characters",
    (() => {
      const buf = new Uint8Array(SEED_BYTES);
      crypto.getRandomValues(buf);
      return Array.from(buf).map((b) => b.toString(16).padStart(2, "0")).join("").length === 64;
    })(),
  );
}

// ---- the OOD point is out of domain by construction, not by luck ----
function oodClaims() {
  for (const [F, nStar, K] of [[GF, 3, 3], [GF4, 2, 3]] as [Field<any>, number, number][]) {
    const params = deriveParams(nStar, K);
    const domain = positionDomain(F, params.T);
    let checked = 0;
    let inDomain = 0;
    for (let i = 0; i < 60; i++) {
      const k = keyGen(F, nStar, K, `ood-${F.id}-${i}`);
      if (domain.has(F.fmtFull(k.ood.x))) inDomain++;
      checked++;
    }
    check(`${F.name}: OOD point is never a position (${checked} keys)`,
      inDomain === 0 && checked === 60);
  }

  // Force the rejection branch: a draw source that returns a DOMAIN point first.
  // Without rejection sampling this returns psi(3) and the check below fails.
  const params = deriveParams(3, 3);
  const domain = positionDomain(GF, params.T);
  const collide = psi(GF, 3);
  let draws = 0;
  const rigged = (_tag: string, _inputs: string[], _count: number): bigint[] => {
    draws++;
    return draws === 1 ? [collide] : [collide + BigInt(draws)];
  };
  const z = deriveOOD(GF, "jv-000000000000", domain, rigged);
  check("deriveOOD rejects a first draw that lands in the position domain",
    draws >= 2 && !GF.eq(z, collide) && !domain.has(GF.fmtFull(z)));
  check("…and the rigged source really produced a domain point first",
    domain.has(GF.fmtFull(collide)));
}

// ---- what the exported transcript does and does not prove ----
function transcriptClaims() {
  const build = (seed: string) => {
    const key = keyGen(GF, 2, 3, seed);
    const ledger = new Ledger(key);
    let n = 0;
    while (!checkCliff(key, ledger).reached && n < 8) {
      const dr = findDisjointMessage(key, ledger.usedX(), n * 1000);
      ledger.add(sign(key, dr.message, ++n, ledger.usedX()));
    }
    return { key, t: exportTranscript(key, ledger) };
  };
  const mine = build("transcript-mine");
  const theirs = build("transcript-theirs");

  const unanchored = verifyTranscript(mine.t);
  check("an honest transcript is internally consistent",
    unanchored.ok && unanchored.code === "OK_INTERNALLY_CONSISTENT" && !unanchored.anchored);

  // THE point of the split: an unanchored pass is not provenance.
  const forged = verifyTranscript(theirs.t);
  check("a transcript from a DIFFERENT key also passes the unanchored check",
    forged.ok && !forged.anchored && mine.key.fingerprint !== theirs.key.fingerprint);
  check("…and is REJECTED once anchored to the expected fingerprint",
    verifyTranscript(theirs.t, mine.key.fingerprint).code === "ANCHOR_MISMATCH");
  check("the right transcript anchors successfully",
    (() => {
      const r = verifyTranscript(mine.t, mine.key.fingerprint);
      return r.ok && r.anchored && r.code === "OK_ANCHORED";
    })());

  // Every self-describing field must be load-bearing. Each mutation names the
  // code it must produce, so a mutation rejected for the WRONG reason still fails.
  const clone = (): Transcript => JSON.parse(JSON.stringify(mine.t));
  const cases: [string, (c: any) => void, string][] = [
    ["scheme", (c) => { c.scheme = "nope"; }, "BAD_SCHEMA"],
    ["version", (c) => { c.version = 99; }, "BAD_VERSION"],
    ["field", (c) => { c.field = "bogus"; }, "BAD_FIELD"],
    ["fingerprint shape", (c) => { c.fingerprint = "abc"; }, "BAD_SCHEMA"],
    ["rootHint shape", (c) => { c.rootHint = "hello"; }, "BAD_SCHEMA"],
    ["rootHint swapped for another key's", (c) => { c.rootHint = theirs.t.rootHint; }, "BAD_OOD"],
    // Each params case must violate EXACTLY ONE identity, or a later check
    // catches it and the earlier check can be deleted without any test noticing.
    // (M = 999 used to be "caught" only because D != M-1 then fired too.)
    ["params: M != (n*+1)K, others intact", (c) => { c.params.K += 1; }, "BAD_PARAMS"],
    ["params: D != M-1, others intact", (c) => { c.params.D = c.params.M; }, "BAD_PARAMS"],
    ["params: T != 2M, others intact", (c) => { c.params.T = 2 * c.params.M + 2; }, "BAD_PARAMS"],
    ["params: nCliff != n*+1, others intact", (c) => { c.params.nCliff = c.params.nStar + 2; }, "BAD_PARAMS"],
    ["params: non-integer", (c) => { c.params.K = 2.5; }, "BAD_PARAMS"],
    ["ood x altered", (c) => { c.ood.x = ["1234"]; }, "BAD_OOD"],
    ["ood y altered", (c) => { c.ood.y = ["1234"]; }, "BAD_OOD"],
    ["duplicate points", (c) => { c.points = c.points.concat(c.points); }, "BAD_POINTS"],
    ["malformed coordinate", (c) => { c.points[1].y = ["not-a-number"]; }, "BAD_POINTS"],
    ["wrong coordinate count", (c) => { c.points[1].x = ["1", "2", "3", "4"]; }, "BAD_POINTS"],
    // DISTINCT points, so only the size cap can reject this — filling with
    // copies was caught by the duplicate check instead, leaving the cap untested.
    ["point-count flood (all distinct)", (c) => {
      c.points = Array.from({ length: 5000 }, (_, i) => ({
        x: [(BigInt(c.points[0].x[0]) + BigInt(i) * 7919n).toString()],
        y: [(BigInt(c.points[0].y[0]) + BigInt(i)).toString()],
      }));
    }, "BAD_POINTS"],
  ];
  let mutations = 0;
  for (const [name, mutate, code] of cases) {
    const c = clone();
    mutate(c);
    const r = verifyTranscript(c);
    check(`tampered transcript rejected [${code}]: ${name}`, !r.ok && r.code === code);
    mutations++;
  }
  check("the tamper sweep actually ran every case", mutations === cases.length);

  const short = clone();
  short.points = short.points.slice(0, short.params.D);
  check("a transcript short of D+1 points is rejected as insufficient",
    verifyTranscript(short).code === "INSUFFICIENT_POINTS");
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

  hiddenClaims();
  oodClaims();
  transcriptClaims();

  console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
