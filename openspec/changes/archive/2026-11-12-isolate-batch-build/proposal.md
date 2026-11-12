# Proposal: Isolate Batch Build and Target Sdkconfig

## Why

When building multi-target firmwares via `python3 tools/package_firmware.py --all`, compilation fails with `Project sdkconfig was generated for target 'X', but CMakeCache.txt contains 'Y'` because ESP-IDF defaults to mutating a single shared `<repo_root>/sdkconfig` across all target builds. Furthermore, the batch packaging tool creates multiple `build_<target>` directories directly under the repository root, cluttering the workspace and risking collisions with the developer's daily VS Code / clangd development environment which relies on `<repo_root>/build`.

Isolating batch builds into `build_batch/<target>/` with dedicated per-target `sdkconfig` files prevents target configuration contamination, protects the primary VS Code development environment, and keeps the repository root clean.

## What Changes

- **Unified Batch Build Location**: Consolidate multi-target build directories under `build_batch/<target>/` (e.g., `build_batch/esp32s3/`, `build_batch/esp32c3/`) instead of flat `build_<target>` directories in the project root.
- **Per-Target Sdkconfig Isolation**: Direct ESP-IDF CMake to generate and use `build_batch/<target>/sdkconfig` via `-DSDKCONFIG=<path>` for both `set-target` and `build` commands. The root `<repo_root>/sdkconfig` is never touched or mutated during batch builds.
- **VS Code Development Preservation**: Preserve `<repo_root>/build` exclusively for single-target IDE development, debugging, and clangd language server index generation.
- **Robust Cache Re-use**: Update `package_firmware.py` target detection to verify both `CMakeCache.txt` and the target-specific `sdkconfig`, allowing safe and fast incremental builds without full rebuilds.
- **Packaging Fallback Compatibility**: Allow `--package-only` to search `build_batch/<target>` first, falling back to `<repo_root>/build` if packaging an IDE-compiled image.

## Capabilities

### Modified Capabilities
- `firmware-packaging`: Update multi-target build orchestration requirements to use unified batch build directories (`build_batch/<target>`) and target-isolated SDKCONFIG paths rather than flat root build directories and shared root configuration.

## Impact

- **Tooling**: `tools/package_firmware.py` CLI and orchestration logic.
- **Filesystem**: Output directories during build move to `build_batch/` (already ignored by `.gitignore` rule `build_*/`).
- **Developer Experience**: VS Code `clangd` and ESP-IDF extension remains untouched and stable during and after batch release packaging.
