# Spec Delta: firmware-packaging

## MODIFIED Requirements

### Requirement: Multi-Target Build Orchestration
The firmware packaging tool SHALL support orchestrated compilation across all supported target architectures (esp32s3, esp32s2, esp32c3, esp32c5, esp32c6, esp32p4, esp32s31) using isolated subdirectories under `build_batch/<target>` and target-isolated SDKCONFIG paths to prevent configuration and cache contamination.

#### Scenario: Compiling all targets
- **WHEN** user executes packaging tool with `--all` flag under an active ESP-IDF environment
- **THEN** the tool compiles each supported target sequentially into dedicated `build_batch/<target>` directories with isolated `sdkconfig` files without cross-target cache interference or mutating `<repo_root>/sdkconfig`

#### Scenario: Compiling subset of targets
- **WHEN** user executes packaging tool with `--target` followed by one or more target names
- **THEN** the tool compiles only the specified targets into their respective `build_batch/<target>` directories

#### Scenario: Missing ESP-IDF environment
- **WHEN** user executes packaging tool without active ESP-IDF environment variables
- **THEN** the tool halts with a clear error explaining missing IDF_PATH or toolchain binaries

## ADDED Requirements

### Requirement: Workspace and IDE Environment Isolation
The firmware packaging tool SHALL isolate batch build artifacts from the primary IDE build directory (`build/`) to protect IDE language server indexes and single-target development environments.

#### Scenario: Preserving IDE development build directory
- **WHEN** packaging tool compiles firmware targets
- **THEN** the tool leaves `<repo_root>/build` and `<repo_root>/sdkconfig` unmodified

#### Scenario: Packaging from IDE build fallback
- **WHEN** user executes packaging tool with `--package-only` for a target and no `build_batch/<target>` exists
- **THEN** the tool checks if `<repo_root>/build` matches the requested target and packages from it
