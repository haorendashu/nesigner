# Proposal

## Why

nesigner now supports multiple ESP32 target architectures (ESP32-S3, ESP32-S2, ESP32-C3, ESP32-C5, ESP32-C6, ESP32-P4, and ESP32-S31). Currently, building and packaging firmware for these targets requires manual invocation of `idf.py` with repetitive configuration steps, risking build directory contamination and missing binary offsets. Furthermore, web-based flashing tools (such as Web Serial flashers in `nesigner_website`) need structured output directories containing individual binaries (`bootloader.bin`, `partition-table.bin`, `nesigner.bin`), a unified full-image binary (`nesigner_merged.bin`), and a machine-readable manifest (`manifest.json`) indicating flash offsets and chip families.

Providing a dedicated packaging script automates multi-target compilation, organizes release binaries cleanly by target, and prepares ready-to-burn artifacts for web flashing without manual intervention.

## What Changes

- Add a cross-platform Python packaging tool `tools/package_firmware.py` to automate multi-target compilation and artifact packaging.
- Support compiling and packaging all supported targets (`esp32s3`, `esp32s2`, `esp32c3`, `esp32c5`, `esp32c6`, `esp32p4`, `esp32s31`) or specific selected targets.
- Implement isolated build directories (`build_<target>/`) to prevent cache collision across different MCU architectures.
- Extract flashing offsets dynamically from ESP-IDF `flasher_args.json` to prevent offset hardcoding errors.
- Generate a single merged binary (`nesigner_merged.bin`) for each target using `esptool.py merge_bin` for single-operation flashing.
- Generate a unified `manifest.json` describing available targets, chip families, offsets, and binary paths for web flashers.
- Organize outputs cleanly under `dist/<version>/<target>/` with flexible command-line options (`--target`, `--all`, `--output-dir`, `--version`, `--package-only`).

## Capabilities

### New Capabilities
- `firmware-packaging`: Defines automated multi-target build orchestration, binary extraction, full-image merging, and web flashing manifest generation.

### Modified Capabilities
*(None. Existing hardware transport and target configuration specs remain unchanged.)*

## Impact

- **New Files**: `tools/package_firmware.py` (and optional documentation/helper scripts under `tools/`).
- **Dependencies**: Requires Python 3, active ESP-IDF environment (with `idf.py` and `esptool.py` available in PATH), and Git for version detection.
- **Affected Systems**: Firmware release workflow and future web flashing frontend integration (`nesigner_website`). Existing firmware source code in `main/` and `components/` is not modified.
