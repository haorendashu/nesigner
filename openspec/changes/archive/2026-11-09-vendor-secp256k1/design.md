# Design: Vendored secp256k1 and Legacy Submodule Cleanup

## Context

See `proposal.md` for motivation. Currently, `components/secp256k1` contains its own `.git` metadata and custom ESP-IDF CMake logic (`if(ESP_PLATFORM) idf_component_register(...) ... endif()`). Because it was never tracked in Git, fresh repository clones cannot build. Meanwhile, `components/cJSON` remains registered as a Git submodule in `.gitmodules`, despite the project having migrated to `managed_components/espressif__cjson` in ESP-IDF v6.1.

## Goals / Non-Goals

**Goals:**
- Eliminate the nested Git metadata in `components/secp256k1` and commit the patched component directly to the project's Git repository (vendoring).
- Prune unused non-ESP upstream files (such as `.git/`, `ci/`, `sage/`, `doc/`, `autotools-aux/`) to keep repository size lean.
- Cleanly unregister and remove the obsolete `components/cJSON` submodule and `.gitmodules`.
- Ensure clean-clone builds succeed immediately without external network or submodule operations.

**Non-Goals:**
- Modifying cryptographic logic, precomputed lookup tables, or compiler flags (`USE_FIELD_10X26=1`, `ENABLE_MODULE_SCHNORRSIG=1`, etc.) in `secp256k1`.
- Publishing `secp256k1` to the public Espressif Component Registry.
- Changing `main/crypto/crypto_secp256k1.c` or its public C APIs.

## Decisions

### Decision 1: Full In-Repo Vendoring over Git Submodule or Component Registry
- **Choice**: Strip `.git` from `components/secp256k1` and track the source files directly in `nesigner`.
- **Rationale**: Firmware builds must be self-contained and reproducible. Git submodules introduce friction (users forgetting `--recursive`, detached HEAD issues, submodule tracking conflicts with `IDF_SKIP_CHECK_SUBMODULES=1`). Referencing an external Git repository via `idf_component.yml` makes builds fragile in restricted or offline network environments. Vendoring guarantees 100% build reliability out of the box.
- **Alternatives Considered**:
  - *Git Submodule*: Preserves upstream commit history, but breaks clean build simplicity and requires maintaining a separate fork repo.
  - *IDF Component Manager Git Dependency*: Requires stable GitHub network access during build and fails in offline environments.

### Decision 2: Pruning Non-Essential Upstream Artifacts
- **Choice**: Retain only the files required for ESP-IDF builds:
  - `src/` (core C source, headers, and precomputed lookup tables)
  - `include/` (public API headers: `secp256k1.h`, `secp256k1_schnorrsig.h`, `secp256k1_extrakeys.h`, `secp256k1_ecdh.h`)
  - `CMakeLists.txt` (containing the ESP-IDF component registration)
  - `idf_component.yml` (local component manifest)
  - `COPYING` / `README.md` (licensing and documentation)
  Remove: `.git/`, `.github/`, `ci/`, `sage/`, `doc/`, `examples/`, `tools/`, `autotools-aux/`, `configure.ac`, `Makefile.am`.
- **Rationale**: Upstream auxiliary files add ~3MB of bloat and Autotools clutter that are never invoked by ESP-IDF CMake.

### Decision 3: Removal of Obsolete `components/cJSON` Submodule
- **Choice**: Run `git rm components/cJSON` and remove `.gitmodules` and `.git/modules/components/cJSON`.
- **Rationale**: ESP-IDF v6.1 automatically resolves `espressif/cjson` into `managed_components/espressif__cjson`. The submodule in `components/cJSON` is unused dead code that causes confusion.

## Risks / Trade-offs

- **[Repository Storage Footprint]** → Vendoring `secp256k1` adds ~6.8MB to the Git repository (primarily the 6.2MB precomputed ecmult table in `src/precomputed_ecmult.c`).
  *Mitigation*: 6.8MB is modest for a modern Git repository, and having precomputed tables avoids expensive at-build generator scripts or slow runtime point multiplications.
- **[Upstream Tracking]** → Changes from `bitcoin-core/secp256k1` will not sync automatically.
  *Mitigation*: The secp256k1 Schnorr/ECDH algorithms and Nostr curve constants are fixed and stable. Updates are rarely required and can be re-vendored manually when necessary.
