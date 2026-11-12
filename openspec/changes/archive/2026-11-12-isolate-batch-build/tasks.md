# Tasks

## 1. Directory and Path Configuration

- [x] 1.1 Update `tools/package_firmware.py` to route batch build directories to `build_batch/<target>` instead of root `build_<target>` and verify directories are created under `build_batch/`
- [x] 1.2 Add configurable `--build-batch-dir` argument (defaulting to `build_batch`) in `tools/package_firmware.py` and verify `--help` documents it

## 2. Sdkconfig Isolation and Build Command Updates

- [x] 2.1 Update `build_target()` in `tools/package_firmware.py` to pass `-D SDKCONFIG=<build_dir>/sdkconfig` to `idf.py set-target` and verify `build_dir/sdkconfig` is generated without mutating `<repo_root>/sdkconfig`
- [x] 2.2 Update `build_target()` in `tools/package_firmware.py` to pass `-D SDKCONFIG=<build_dir>/sdkconfig` to `idf.py build`
- [x] 2.3 Refactor cache detection logic in `build_target()` to check both `CMakeCache.txt` and `build_dir/sdkconfig`, verifying that stale builds trigger clean reconfiguration

## 3. Packaging Fallback and Multi-Target Verification

- [x] 3.1 Update `--package-only` target search logic to look in `build_batch/<target>`, falling back to `<repo_root>/build` if an IDE build matches the requested target
- [x] 3.2 Run multi-target build across `esp32s3`, `esp32s2`, and `esp32c3` to verify sequential builds succeed without SDKCONFIG target mismatch errors
- [x] 3.3 Verify `<repo_root>/build` and `<repo_root>/sdkconfig` remain untouched and clean after the batch packaging run
