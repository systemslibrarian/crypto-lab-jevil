// Standalone transcript verifier — the auditable path.
//
//   npm run verify <transcript.json>
//   npm run verify <transcript.json> --expected-fingerprint <hex>
//
// It imports only verifyTranscript, which uses *public* data: it reconstructs
// the key from the transcript's revealed points by Lagrange interpolation and
// checks the result against a fingerprint.
//
// WHICH fingerprint is the whole question, and this used to print "VERIFIED"
// without distinguishing:
//
//   - With no --expected-fingerprint, the only fingerprint available is the one
//     stored INSIDE the transcript. Matching it proves the points interpolate to
//     a key whose hash is the hash in the same file — internal consistency. A
//     transcript exported from any other key passes identically (measured), so
//     this says nothing about provenance.
//   - With --expected-fingerprint, taken from the key panel or any source other
//     than this file, a match additionally proves the transcript belongs to that
//     advertised public key.
import { readFileSync } from "node:fs";
import { verifyTranscript } from "../src/jevil";

const argv = process.argv.slice(2);
const path = argv.find((a) => !a.startsWith("--"));
const fpIdx = argv.indexOf("--expected-fingerprint");
const expected = fpIdx >= 0 ? argv[fpIdx + 1] : undefined;

if (!path) {
  console.error("usage: npm run verify <transcript.json> [--expected-fingerprint <hex>]");
  process.exit(2);
}
if (fpIdx >= 0 && (!expected || expected.startsWith("--"))) {
  console.error("--expected-fingerprint requires a value");
  process.exit(2);
}

const t = JSON.parse(readFileSync(path, "utf8"));
const r = verifyTranscript(t, expected);

console.log(`scheme:    ${t.scheme} v${t.version}`);
console.log(`field:     ${t.field}`);
console.log(`params:    n*=${t.params?.nStar} K=${t.params?.K} D=${t.params?.D} (cliff at sig ${t.params?.nCliff})`);
console.log(`points:    ${r.distinct} distinct / ${r.needed} needed`);
console.log(`fingerprint in file:  ${t.fingerprint}`);
console.log(`fingerprint recovered: ${r.recoveredFingerprint ?? "—"}`);
console.log(`fingerprint expected:  ${expected ?? "— (none supplied)"}`);

if (!r.ok) {
  console.log(`\n✗ NOT VERIFIED [${r.code}] — ${r.reason}`);
} else if (r.anchored) {
  console.log(
    `\n✓ VERIFIED against the expected public key [${r.code}] — ${r.reason}`,
  );
} else {
  console.log(`\n~ INTERNALLY CONSISTENT [${r.code}] — ${r.reason}`);
  console.log(
    "  This is NOT proof the transcript belongs to any particular key. Re-run with\n" +
      "  --expected-fingerprint <fp>, using a fingerprint you obtained independently\n" +
      "  of this file, to make that claim.",
  );
}
process.exit(r.ok ? 0 : 1);
