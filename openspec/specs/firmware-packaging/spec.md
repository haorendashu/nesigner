# firmware-packaging Specification

## Purpose

Automates multi-target ESP32 firmware compilation, isolated artifact extraction, full-image binary merging, and structured distribution manifest generation for web flashing tools.

## Requirements

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

### Requirement: Workspace and IDE Environment Isolation
The firmware packaging tool SHALL isolate batch build artifacts from the primary IDE build directory (`build/`) to protect IDE language server indexes and single-target development environments.

#### Scenario: Preserving IDE development build directory
- **WHEN** packaging tool compiles firmware targets
- **THEN** the tool leaves `<repo_root>/build` and `<repo_root>/sdkconfig` unmodified

#### Scenario: Packaging from IDE build fallback
- **WHEN** user executes packaging tool with `--package-only` for a target and no `build_batch/<target>` exists
- **THEN** the tool checks if `<repo_root>/build` matches the requested target and packages from it

### Requirement: Binary Extraction and Organization
The packaging tool SHALL extract bootloader, partition table, and application binaries from build directories and organize them into target-specific release folders under the specified distribution path.

#### Scenario: Extracting partition and application binaries
- **WHEN** a target build finishes successfully
- **THEN** the tool copies `bootloader.bin`, `partition-table.bin`, and `nesigner.bin` to `dist/<version>/<target>/`

#### Scenario: Preserving build metadata
- **WHEN** organizing target artifacts
- **THEN** the tool copies `flasher_args.json` alongside target binaries for verification

### Requirement: Merged Full-Image Generation
The packaging tool SHALL invoke `esptool.py merge_bin` using target-specific flash parameters and offsets to produce a single contiguous binary image starting at offset 0x0.

#### Scenario: Generating unified binary
- **WHEN** target binaries are extracted and flasher arguments are resolved
- **THEN** the tool creates `nesigner_merged.bin` at offset 0x0 compatible with direct web flashing

### Requirement: Web Flasher Manifest Generation
The packaging tool SHALL generate a top-level `manifest.json` describing all packaged targets, chip families, binary paths, flash offsets, and flash parameters.

#### Scenario: Generating valid manifest
- **WHEN** all selected targets have been packaged
- **THEN** the tool generates `dist/<version>/manifest.json` with target names, chip families, split binary offsets, and merged binary paths
