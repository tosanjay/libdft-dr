# EWAHBoolArray (vendored)

This directory vendors the [EWAHBoolArray](https://github.com/lemire/EWAHBoolArray)
header-only library by Daniel Lemire, used by `tagmap.cpp` for the per-byte
offset-set representation behind the interned-label tag map.

Headers vendored (5 files, ~4.3k LOC total):
- `ewah.h`
- `ewah-inl.h`
- `ewahutil.h`
- `boolarray.h`
- `runninglengthword.h`

Vendored at version `0.4.0` (matches the headers shipped to `/usr/include`
on the development host). Sourced from <https://github.com/lemire/EWAHBoolArray>.

**License:** Apache 2.0 — see `LICENSE` in this directory. Compatible
with libdft-dr's BSD-3-Clause umbrella under standard permissive-license
redistribution terms.

**Why vendored:** EWAHBoolArray is not packaged in the Ubuntu apt
archive, and GitHub Actions runners are fresh installs. Vendoring keeps
the build self-contained — clone + cmake + build, no additional setup.

To upgrade: replace the 5 headers with their newer counterparts and
re-run `tests/run_smoke.sh` to confirm no API drift.
