# Design: Batch Build and Sdkconfig Isolation

## Context

See `proposal.md` for motivation. Currently, `tools/package_firmware.py` generates target build directories in the project root (`build_<target>/`) and invokes `idf.py` without specifying `-DSDKCONFIG`. Consequently:
1. ESP-IDF mutates `<repo_root>/sdkconfig` sequentially on every target build.
2. Any target that skips `set-target` via cache detection fails with target mismatch error against the shared `<repo_root>/sdkconfig`.
3. Multiple `build_<target>` directories clutter the root directory and create potential ambiguity with `<repo_root>/build` used by VS Code and `clangd`.

## Goals / Non-Goals

**Goals:**
- Direct all multi-target packaging builds to `build_batch/<target>/`.
- Isolate the generated `sdkconfig` to `build_batch/<target>/sdkconfig` via `-DSDKCONFIG`.
- Maintain complete isolation from `<repo_root>/build` to preserve VS Code `clangd` language server index and single-board development.
- Improve build cache detection so targets can be rebuilt incrementally without target mismatch or cache thrashing.
- Support `--package-only` fallback to `<repo_root>/build` if packaging a developer's local IDE build.

**Non-Goals:**
- Modifying target default configurations (`sdkconfig.defaults.*`).
- Changing release distribution structure under `dist/<version>/`.
- Modifying VS Code workspace settings.

## Decisions

### Decision 1: Directory Naming `build_batch/<target>/`
- **Choice**: Use `build_batch/<target>/` as the default location for batch builds.
- **Rationale**:
  - Matches the existing `.gitignore` wildcard pattern `build_*/` without needing `.gitignore` changes.
  - Leaves `<repo_root>/build` completely undisturbed for daily single-target IDE development and `clangd` language server indexing.
  - Simplifies cleanup: a single `rm -rf build_batch` cleans all multi-target compilation artifacts without affecting IDE state.
- **Alternatives Considered**:
  - `build/<target>`: Would nest batch targets inside `build/`. However, running `idf.py fullclean` in IDE or VS Code tasks could inadvertently wipe all batch target caches, or IDE clangd might crawl subdirectories.
  - Flat `build_<target>` in root: Pollutes repository root as target hardware count grows.

### Decision 2: SDKCONFIG Isolation via `-DSDKCONFIG=<build_dir>/sdkconfig`
- **Choice**: Pass `-D SDKCONFIG=<build_dir>/sdkconfig` to both `idf.py set-target` and `idf.py build`.
- **Rationale**:
  - ESP-IDF Kconfig natively resolves defaults from root `sdkconfig.defaults` and `sdkconfig.defaults.<target>`, and outputs the resolved full configuration directly to `<build_dir>/sdkconfig`.
  - `<repo_root>/sdkconfig` is never created, modified, or backed up, avoiding workspace git dirtiness.
- **Alternatives Considered**:
  - Backing up and restoring `<repo_root>/sdkconfig` during build: Brittle if process is interrupted (Ctrl+C).
  - Removing cache check and forcing `set-target` each time: Extremely slow because `set-target` triggers `fullclean` on every run.

### Decision 3: Comprehensive Cache Validation
- **Choice**: Consider a build directory configured only when:
  1. `CMakeCache.txt` exists and contains `IDF_TARGET:STRING={target}`.
  2. `build_dir / "sdkconfig"` exists and contains `CONFIG_IDF_TARGET="{target}"`.
- **Rationale**: Ensures that stale directories generated prior to this change (which lacked `build_dir/sdkconfig`) are automatically reconfigured with `set-target` rather than failing during compilation.

## Risks / Trade-offs

- **[Risk] Existing legacy `build_<target>` folders remain in root** → Mitigation: Script logs notice recommending removal of obsolete `build_<target>` folders.
- **[Risk] First batch build generates all 7 target configurations from scratch** → Mitigation: One-time configuration cost; all subsequent runs benefit from isolated incremental caching without target conflicts.
