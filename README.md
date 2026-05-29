# TEA: Triple-Entry Accounting prototype

A working reference implementation of the triple-entry accounting (TEA) artefact described in:

> Wright, C. (2026). *Triple-Entry Accounting with Deterministic Invoice-Payment Notes, Hierarchical Keys, and Verifiable Private Linkage on a Public Ledger: A Design-Science Methodology for Inter-Organisational Accounting Evidence.* Manuscript ACCINF-D-26-00069, International Journal of Accounting Information Systems.

The artefact treats the triple-entry "third entry" as an evidence object: a public anchor attesting that private invoice and payment records existed and are linked, with disclosure to auditors scoped to individual fields and bound by signed authorisation. This repository is a self-contained Python prototype that implements the core protocol, generates deterministic worked-example test vectors, and runs a synthetic-population evaluation at realistic annual volume.

## What's in here

| File | Purpose |
|---|---|
| `refimpl.py` | Reference implementation. Curve secp256k1, SHA-256, HKDF-SHA256, ECDSA with low-S RFC 6979 deterministic nonces. Computes the canonical worked-example vectors that the paper's Appendix C contains (master keys, derived sub-keys, ECDH shared value, K_master, linkage tags, per-field keys, per-field commitments, note body, signature). |
| `simstudy.py` | Population-scale simulation using the same primitives as the reference implementation, with real ECDSA signing on a representative sample. Generates 80,000 invoices and 76,000 linked payments over 400 counterparties, builds Merkle batches, injects three fault classes, and runs the deterministic reconciliation. |
| `simstudy2.py` | Faster stdlib-only variant of the same simulation (hashing/commitment/Merkle/reconciliation only; per-operation crypto cost taken from the paper's Table 11 measured medians). Produces the numbers reported in Section 10.5a of the manuscript. |
| `examples/simstudy2_v213_output.txt` | Captured stdout of the `simstudy2.py` run cited in the v213 manuscript, for line-by-line comparison. |
| `figures/fig1.svg` | Figure 1: End-to-end evidence flow. |
| `figures/fig2.svg` | Figure 2: Per-field key derivation and the scoped disclosure envelope. |

## What this is and is not

**It is** an executable prototype of the bilateral protocol: shared-value derivation, hierarchical key material, per-field commitments, note structure, signing/verification, Merkle batching, and deterministic reconciliation. The `refimpl.py` outputs are deterministic and reproducible from the seeds and constants declared in the source.

**It is not** a production system. It runs in pure Python with the small `ecdsa` library; production deployments would use a constant-time native curve library and proper key custody. It does not include ERP integration glue, threshold-custody operational tooling, or any deployment to a specific public medium — those are control-dependent choices the paper discusses but the prototype does not bind.

## Install

Requires Python 3.10 or later.

```
pip install -r requirements.txt
```

`simstudy2.py` runs against the standard library alone; `refimpl.py` and `simstudy.py` need `ecdsa>=0.19`.

## Run

```
python refimpl.py
```
Prints the deterministic worked-example vectors. The values are bit-identical to the corresponding hexadecimal targets in Appendix C of the manuscript.

```
python simstudy.py
```
Runs the population-scale simulation with real ECDSA signing on a 2,000-note sample, used to extrapolate signing cost across the full year. Takes a few minutes on contemporary hardware.

```
python simstudy2.py
```
Runs the faster stdlib-only variant. Bit-deterministic counts (80,000 invoices, 76,000 payments, 156,000 notes, 461-byte note size, 36.9 MB note data, 156 Merkle batches, 380/228/160 injected faults, 768/768 detection, 99.61% clean recalculable). Wall-clock times are host-dependent and on the order of single-digit seconds end-to-end. Compare your output against `examples/simstudy2_v213_output.txt`.

## Determinism and seeds

`refimpl.py` uses fixed scalar masters (`0x11…11`, `0x22…22`) so the worked example is reproducible bit-for-bit across hosts.

`simstudy.py` and `simstudy2.py` seed Python's PRNG with `random.seed(20260528)` for population structure and amount draws; the only host-dependent values are the wall-clock measurements.

Fault injection in both simulations uses `os.urandom`, so the *identities* of injected orphan tags differ across runs by design (security-property reasons in the paper), but the *counts* and *detection rates* are deterministic.

## What the prototype demonstrates relative to the paper

| Paper section | Where it lives in this repo |
|---|---|
| §6 hierarchical keys | `refimpl.py` lines 34–47 |
| §7 selective disclosure (key derivation half) | `refimpl.py` lines 49–55 |
| §8 note structure and signing | `refimpl.py` lines 67–80 |
| §10.4 cost layer | timings inside `simstudy.py` |
| §10.5 measured cryptographic core | `refimpl.py` worked example; `simstudy.py` ECDSA sample |
| §10.5a synthetic-population evaluation | `simstudy2.py` + `examples/simstudy2_v213_output.txt` |
| Appendix C worked-example test vectors | `refimpl.py` stdout |
| Figure 1 (evidence flow) | `figures/fig1.svg` |
| Figure 2 (key derivation) | `figures/fig2.svg` |

## Limitations explicitly carried over from the paper

This prototype does not address the garbage-in problem: if both parties agree to record a fictitious transaction and both publish well-formed notes, the artefact records the agreed figures faithfully and the simulation will not flag them. The detective controls catch *post-issuance* alterations and *structural* inconsistencies; collusive false-origin commitments are out of scope by design (see §11.5 of the paper).

Legal admissibility of the cryptographic evidence varies by jurisdiction (§12 of the paper). Nothing in this prototype constitutes legal advice.

## Citing this artefact

Code is licensed under MIT (see `LICENSE`). If you build on it for academic work, please cite the paper above. The canonical Zenodo deposit, which carries the deterministic vectors and the build environment specification used by the published manuscript, is at:

DOI 10.5281/zenodo.20371173

## Author

Craig Wright
University of Exeter
ORCID: 0000-0001-9374-0507
Email: cw881@exeter.ac.uk

## License

MIT. See `LICENSE`.
