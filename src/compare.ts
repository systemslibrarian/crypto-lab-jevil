// src/compare.ts — "soft slope vs sharp cliff", the paper's central thesis,
// drawn from real numbers.
//
// HORS-family few-time signatures (FORS in SLH-DSA, etc.) degrade SOFTLY: after
// an adversary has observed r signatures, the forgery probability is bounded by
// roughly (r·K / T)^K — a smooth curve that creeps upward with every signature.
// Jevil degrades the opposite way: forgery is negligible (~124-bit) through the
// budget n*, then at signature n*+1 the secret key is fully recoverable, so the
// forgery probability snaps to 1. This module plots both against the SAME live
// parameters so the qualitative difference — gentle slope vs vertical wall — is
// visible. (Real FORS uses a far larger T, so its slope stays low much longer;
// the demo's small T just makes the shape legible — see KNOWN-GAPS.md.)

import type { Params } from "./jevil";

/** Classic HORS forgery bound after r signatures: min(1, (r·K / T)^K). */
export function softProb(r: number, K: number, T: number): number {
  if (r <= 0) return 0;
  return Math.min(1, Math.pow((r * K) / T, K));
}

const W = 720;
const H = 300;
const PADL = 54;
const PADR = 16;
const PADT = 22;
const PADB = 46;

export function renderCompare(p: Params): string {
  const xMax = p.nCliff + 1;
  const plotW = W - PADL - PADR;
  const plotH = H - PADT - PADB;
  const sx = (r: number) => PADL + (r / xMax) * plotW;
  const sy = (prob: number) => PADT + (1 - prob) * plotH;
  const baseY = PADT + plotH;

  // Soft curve — the HORS bound, sampled smoothly.
  const samples = 160;
  let soft = "";
  for (let i = 0; i <= samples; i++) {
    const r = (i / samples) * xMax;
    soft +=
      (i === 0 ? "M" : "L") +
      sx(r).toFixed(1) +
      " " +
      sy(softProb(r, p.K, p.T)).toFixed(1) +
      " ";
  }

  // Jevil step — negligible through n*, vertical jump to 1 at the cliff.
  const jevil =
    `M${sx(0).toFixed(1)} ${sy(0).toFixed(1)} ` +
    `L${sx(p.nStar).toFixed(1)} ${sy(0).toFixed(1)} ` +
    `L${sx(p.nCliff).toFixed(1)} ${sy(0).toFixed(1)} ` +
    `L${sx(p.nCliff).toFixed(1)} ${sy(1).toFixed(1)} ` +
    `L${sx(xMax).toFixed(1)} ${sy(1).toFixed(1)}`;

  let xticks = "";
  for (let r = 0; r <= xMax; r++) {
    const x = sx(r).toFixed(1);
    xticks +=
      `<line class="cmp-tick" x1="${x}" y1="${baseY}" x2="${x}" y2="${baseY + 5}"/>` +
      `<text class="cmp-axt" x="${x}" y="${baseY + 18}" text-anchor="middle">${r}</text>`;
  }

  const cliffX = sx(p.nCliff).toFixed(1);
  const safeX = sx(p.nStar).toFixed(1);

  return `
  <svg viewBox="0 0 ${W} ${H}" class="cmp-svg" role="img"
    aria-label="Forgery probability versus number of signatures. A soft few-time signature scheme rises gradually with each signature. Jevil stays negligible through signature ${p.nStar}, then jumps to certain forgery at the cliff, signature ${p.nCliff}.">
    <line class="cmp-axis" x1="${PADL}" y1="${PADT}" x2="${PADL}" y2="${baseY}"/>
    <line class="cmp-axis" x1="${PADL}" y1="${baseY}" x2="${W - PADR}" y2="${baseY}"/>
    <text class="cmp-axl" x="${PADL - 8}" y="${PADT + 5}" text-anchor="end">1</text>
    <text class="cmp-axl" x="${PADL - 8}" y="${baseY + 4}" text-anchor="end">0</text>
    <text class="cmp-axttl" transform="translate(15 ${PADT + plotH / 2}) rotate(-90)" text-anchor="middle">forgery probability</text>
    <text class="cmp-axttl" x="${PADL + plotW / 2}" y="${H - 6}" text-anchor="middle">signatures from one key</text>
    ${xticks}
    <rect class="cmp-safe" x="${PADL}" y="${PADT}" width="${Number(safeX) - PADL}" height="${plotH}"/>
    <text class="cmp-safelbl" x="${(PADL + Number(safeX)) / 2}" y="${baseY - 8}" text-anchor="middle">within budget</text>
    <line class="cmp-cliff" x1="${cliffX}" y1="${PADT}" x2="${cliffX}" y2="${baseY}"/>
    <text class="cmp-clifflbl" x="${cliffX}" y="${PADT - 7}" text-anchor="middle">cliff · n*+1</text>
    <path class="cmp-soft" d="${soft.trim()}"/>
    <path class="cmp-jevil" d="${jevil}"/>
  </svg>`;
}
