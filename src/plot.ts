// src/plot.ts — the cliff plot (SVG).
//
// ILLUSTRATIVE, by design (see KNOWN-GAPS.md). The real secret lives over the
// 64-bit Goldilocks field, where plotting f(g^i) does not produce a smooth
// curve. So this panel renders the cliff *geometry* in real-number coordinate
// space — a faithful picture of the underlying fact the scheme exploits:
//
//   • below D+1 distinct points, infinitely many degree-D polynomials fit
//     (we draw several, all passing through the revealed points);
//   • at D+1 the polynomial snaps to a unique curve (drawn solid red).
//
// The degree D and the revealed-point count are driven by LIVE scheme state, so
// the picture always matches the real ledger. The binding recovery proof
// (recovered f == true f) is done over the real field and shown in Panel 04.

// Small deterministic PRNG (mulberry32) — reproducible curves per key, no
// Math.random (which the project bans as a crypto stand-in; used here only for
// illustrative alternate-curve shapes).
function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Real-number Lagrange interpolation evaluated at a single x.
// nodes: array of [x, y]. Stable enough for the small D this demo plots.
function lagrangeEval(nodes: [number, number][], x: number): number {
  let total = 0;
  for (let i = 0; i < nodes.length; i++) {
    let term = nodes[i][1];
    for (let j = 0; j < nodes.length; j++) {
      if (j === i) continue;
      term *= (x - nodes[j][0]) / (nodes[i][0] - nodes[j][0]);
    }
    total += term;
  }
  return total;
}

export interface PlotState {
  D: number; // polynomial degree
  revealed: number; // distinct points revealed so far (includes OOD)
  cliffReached: boolean;
  seedNum: number; // per-key seed for reproducible curve shapes
}

const W = 720;
const H = 360;
const PAD = 36;

// Map node index (0..D) → plot x; value in [0,1] → plot y.
function sx(i: number, D: number): number {
  if (D === 0) return W / 2;
  return PAD + (i / D) * (W - 2 * PAD);
}
function sy(v: number): number {
  // v in roughly [0,1]; clamp generously so wild interpolation stays on-canvas.
  const c = Math.max(-0.25, Math.min(1.25, v));
  return H - PAD - c * (H - 2 * PAD);
}

function pathFor(nodes: [number, number][], D: number): string {
  const samples = 240;
  let d = "";
  for (let s = 0; s <= samples; s++) {
    const xi = (s / samples) * D; // node-space x in [0, D]
    const yv = lagrangeEval(nodes, xi);
    const px = sx(xi, D);
    const py = sy(yv);
    d += (s === 0 ? "M" : "L") + px.toFixed(1) + " " + py.toFixed(1) + " ";
  }
  return d.trim();
}

/**
 * Build the SVG markup for the current cliff state.
 * Node 0 is the OOD freebie (gold hollow dot); nodes 1..D are signature slots.
 */
export function renderPlot(st: PlotState): string {
  const D = st.D;
  const rng = mulberry32(st.seedNum || 1);

  // The "true" polynomial: fixed y-values at all D+1 nodes (derived from seed).
  const trueY: number[] = [];
  for (let i = 0; i <= D; i++) trueY.push(0.18 + 0.64 * rng());
  const trueNodes: [number, number][] = trueY.map((y, i) => [i, y]);

  // Revealed nodes (the points an observer holds). Cap at D+1.
  const revealed = Math.min(st.revealed, D + 1);
  const revealedNodes: [number, number][] = [];
  for (let i = 0; i < revealed; i++) revealedNodes.push([i, trueY[i]]);

  const parts: string[] = [];
  parts.push(
    `<svg viewBox="0 0 ${W} ${H}" class="cliff-svg" role="img" ` +
      `aria-label="Cliff plot: ${revealed} of ${D + 1} points revealed">`,
  );

  // Frame / axis baseline.
  parts.push(
    `<line class="axis" x1="${PAD}" y1="${H - PAD}" x2="${W - PAD}" y2="${H - PAD}"/>`,
  );
  parts.push(
    `<line class="axis" x1="${PAD}" y1="${PAD}" x2="${PAD}" y2="${H - PAD}"/>`,
  );

  // High-degree real-number interpolation oscillates wildly and is slow, so
  // above this degree we plot only the points (the dots still tell the story).
  const drawCurves = D <= 14;

  if (!drawCurves) {
    parts.push(
      `<text class="plot-note" x="${(W / 2).toFixed(0)}" y="${(PAD + 14).toFixed(0)}" text-anchor="middle">` +
        `degree ${D} — curves omitted; ${revealed} of ${D + 1} points shown</text>`,
    );
  } else if (!st.cliffReached) {
    // BELOW THE CLIFF — draw several distinct degree-D polynomials that all pass
    // through the revealed points. Free nodes (the unrevealed slots) get random
    // values; interpolating gives a genuine alternative that fits the data.
    const ghosts = Math.min(3, D + 1 - revealed > 0 ? 3 : 0);
    for (let g = 0; g < ghosts; g++) {
      const nodes: [number, number][] = revealedNodes.slice();
      for (let i = revealed; i <= D; i++) {
        nodes.push([i, 0.12 + 0.76 * rng()]);
      }
      parts.push(`<path class="ghost-curve" d="${pathFor(nodes, D)}"/>`);
    }
  } else {
    // AT / ABOVE THE CLIFF — the unique recovered polynomial, solid red.
    parts.push(`<path class="recovered-curve" d="${pathFor(trueNodes, D)}"/>`);
  }

  // Dot radius shrinks as the points get dense (high degree).
  const dotR = D > 60 ? 2 : D > 30 ? 3 : D > 14 ? 4 : 6;

  // OOD freebie: gold hollow dot (node 0), shown once revealed.
  if (revealed >= 1) {
    parts.push(
      `<circle class="ood-dot" cx="${sx(0, D).toFixed(1)}" cy="${sy(trueY[0]).toFixed(1)}" r="${dotR + 1}"/>`,
    );
  }
  // Revealed signature points: red filled dots (nodes 1..revealed-1).
  for (let i = 1; i < revealed; i++) {
    parts.push(
      `<circle class="reveal-dot" cx="${sx(i, D).toFixed(1)}" cy="${sy(trueY[i]).toFixed(1)}" r="${dotR}"/>`,
    );
  }
  // Unrevealed slots: faint ticks on the axis to show how many remain.
  for (let i = revealed; i <= D; i++) {
    parts.push(
      `<circle class="empty-slot" cx="${sx(i, D).toFixed(1)}" cy="${(H - PAD).toFixed(1)}" r="${Math.min(3, dotR)}"/>`,
    );
  }

  parts.push("</svg>");
  return parts.join("\n");
}
