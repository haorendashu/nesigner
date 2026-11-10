# Tasks

## 1. Tool Scaffolding & Argument Parsing

- [x] 1.1 Create `tools/package_firmware.py` with CLI argument parser supporting `--target`, `--all`, `--output-dir`, `--version`, and `--package-only`, verifying `--help` outputs correct usage text.
- [x] 1.2 Implement environment verification (checking `IDF_PATH`, `idf.py`, and `esptool.py`) and target validation against supported chips (`esp32s3`, `esp32s2`, `esp32c3`, `esp32c5`, `esp32c6`, `esp32p4`, `esp32s31`), verifying actionable error messages on missing dependencies or invalid targets.

## 2. Build Orchestration & Binary Extraction

- [x] 2.1 Implement multi-target build orchestration using isolated `build_<target>/` directories, verifying clean execution without cross-target configuration interference.
- [x] 2.2 Implement dynamic `flasher_args.json` parser to read flash mode, frequency, size, and binary offsets for bootloader, partition table, and app, verifying correct offsets across different targets.
- [x] 2.3 Implement file copy and artifact organization under `dist/<version>/<target>/`, verifying split binaries (`bootloader.bin`, `partition-table.bin`, `nesigner.bin`) and `flasher_args.json` are placed in the target directory.

## 3. Merged Image & Web Manifest Generation

- [x] 3.1 Integrate `esptool.py merge_bin` invocation to generate a single `nesigner_merged.bin` at offset 0x0 for each target, verifying file creation and size match the combined layout.
- [x] 3.2 Implement `manifest.json` generation in `dist/<version>/manifest.json` indexing all targets, chip families, split binary offsets, and merged binary references, verifying valid JSON output.

## 4. Documentation & End-to-End Verification

- [x] 4.1 Update `README.md` in the repository root to document the new multi-target packaging tool usage, verifying all documented commands match CLI behavior.
- [x] 4.2 Execute verification test with `--target esp32s3 esp32c3 --package-only` (or fresh build), verifying output directory structure and manifest completeness.
