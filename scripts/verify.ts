// Standalone transcript verifier — the auditable path.
//
//   npm run verify <transcript.json>
//
// It imports only verifyTranscript, which uses *public* data: it reconstructs
// the key from the transcript's revealed points by Lagrange interpolation and
// checks the result against the published fingerprint. The secret coefficients
// are never part of the transcript, so a "VERIFIED" result proves the key fell
// out of public data alone.
import { readFileSync } from "node:fs";
import { verifyTranscript } from "../src/jevil";

const path = process.argv[2];
if (!path) {
  console.error("usage: npm run verify <transcript.json>");
  process.exit(2);
}

const t = JSON.parse(readFileSync(path, "utf8"));
const r = verifyTranscript(t);

console.log(`scheme:    ${t.scheme} v${t.version}`);
console.log(`field:     ${t.field}`);
console.log(`params:    n*=${t.params.nStar} K=${t.params.K} D=${t.params.D} (cliff at sig ${t.params.nCliff})`);
console.log(`points:    ${r.distinct} distinct / ${r.needed} needed`);
console.log(`fingerprint published: ${t.fingerprint}`);
console.log(`fingerprint recovered: ${r.recoveredFingerprint ?? "—"}`);
console.log(r.ok ? `\n✓ VERIFIED — ${r.reason}` : `\n✗ NOT VERIFIED — ${r.reason}`);
process.exit(r.ok ? 0 : 1);
