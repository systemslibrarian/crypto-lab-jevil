# crypto-lab-jevil

**Jevil — a catastrophic-failure-by-design signature scheme.** An interactive
browser demo in the [Crypto-Lab](https://systemslibrarian.github.io/) suite.

Most few-time signatures fail *softly* — forgery probability creeps up as you
oversign. Jevil fails the opposite way: a sharp **cliff**. Stay within the budget
`n*` and the key is ~124-bit safe; cross it by a single signature and the secret
key falls out *whole*, reconstructable by anyone from the public record via real
Lagrange interpolation.

> Mechanic from M. Kobeissi, *"Jevil"*, Cryptology ePrint Archive 2026/1103 —
> <https://eprint.iacr.org/2026/1103>.

The cliff is **real**: real Goldilocks-field arithmetic, hash-derived positions,
an accumulating distinct-point ledger, and genuine `O(D²)` Lagrange recovery
verified to reproduce the true secret exactly. See
[`KNOWN-GAPS.md`](./KNOWN-GAPS.md) for an honest accounting of what is faithful
and what is illustrative.

> **For understanding the catastrophic-cliff idea, not for any real signing.**

## Develop

```sh
npm install
npm run dev      # local dev server
npm test         # crypto-core faithfulness proof
npm run build    # type-check + production build
```

Stack: Vite + TypeScript, no framework. Deployed to GitHub Pages.
