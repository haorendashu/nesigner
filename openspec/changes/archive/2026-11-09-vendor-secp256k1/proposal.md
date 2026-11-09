# Proposal: Vendor secp256k1 and Cleanup Legacy Submodules

## Why

Currently, `components/secp256k1` exists as an untracked, nested Git repository with local patches for ESP-IDF integration, while `main/idf_component.yml` references it via a local path (`../components/secp256k1`). Because it was not committed to Git and has no automated download mechanism, cloning the repository on a clean machine results in an immediate build failure. Furthermore, `components/cJSON` remains defined in `.gitmodules` despite being superseded by `managed_components/espressif__cjson` in ESP-IDF v6.1. Vendoring `secp256k1` directly into the repository and cleaning up legacy submodules provides a self-contained, reproducible, zero-network-dependency build across all supported targets.

## What Changes

- **Vendor `components/secp256k1`**: Remove the nested `.git` metadata and prune unused upstream artifacts (such as CI workflows, Sage scripts, autotools auxiliaries, and documentation), tracking the patched ESP-IDF-compatible source directly in Git.
- **Remove legacy `components/cJSON` submodule**: Remove the obsolete `components/cJSON` submodule and `.gitmodules` entries, as cJSON is now managed by the ESP-IDF Component Manager (`managed_components/espressif__cjson`).
- **Update build and target specifications**: Formally specify that `secp256k1` is a vendored local component required across all hardware targets.

## Capabilities

### New Capabilities
None.

### Modified Capabilities
- `target-config`: Clarify and update component dependency requirements to formally mandate vendored `secp256k1` for crypto acceleration across all targets and retire legacy `cJSON` submodule tracking in favor of the managed component.

## Impact

- **Build System**: Clean clones can execute `idf.py build` immediately without missing dependency errors or Git submodule initialization steps.
- **Repository**:
  - `components/secp256k1` is fully tracked in Git (~6.8MB of source, headers, and precomputed tables).
  - `.gitmodules` and `components/cJSON` are removed from version control.
- **Runtime / Firmware**: Zero regression; compiled binary signatures and crypto performance remain unchanged.
