# libdft-dr v0.1 perf benchmarks

Generated: 2026-05-31 12:44:07 UTC
Host: Linux 6.8.0-107-generic x86_64, 8 cores
CPU: Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz
DR: drrun version 10.0.0 -- build 0
Pin: tools/pin-3.20
Iterations per (target, arm): 5 (+1 warmup discarded)

Methodology and caveats: see bench/BENCHMARKS.md.

## tiffcp

- seed: `2.tif` (12658 B, sha256 `571449672045faf3ef67ff2cd21cfcf3a7b1a716532c4000b9e84ac2596a5aa1`)
- SUT: `tiffcp`

| arm | mean (s) | stdev (s) | × native |
|---|---|---|---|
| native       | 0.0116 | 0.0201 | 1.0× |
| dr           | 1.2516 | 0.0123 | 107.9× |
| pin          | 3.4801 | 0.0404 | 300.0× |

**libdft-dr speedup over Pin libdft64:** 2.78×

## xmllint

- seed: `tutorA.rng` (8131 B, sha256 `fcbe19f87668caeff23cc0eaaa3577e78d7f74ed3273f634365e3a0579d92b9d`)
- SUT: `xmllint`

| arm | mean (s) | stdev (s) | × native |
|---|---|---|---|
| native       | 0.0027 | 0.0001 | 1.0× |
| dr           | 1.6038 | 0.0100 | 594.0× |
| pin          | 4.5650 | 0.0522 | 1690.7× |

**libdft-dr speedup over Pin libdft64:** 2.85×

## pdfimages

- seed: `issue1985.pdf` (9884 B, sha256 `0f991f71856c5e88775f48cf194bf4cd3800c27875352473461e16e01750f3d6`)
- SUT: `pdfimages`

| arm | mean (s) | stdev (s) | × native |
|---|---|---|---|
| native       | 0.0085 | 0.0002 | 1.0× |
| dr           | 8.2464 | 0.0635 | 970.2× |
| pin          | 10.1177 | 0.0053 | 1190.3× |

**libdft-dr speedup over Pin libdft64:** 1.23×

