# Tasks

## 1. Clean Up Legacy Submodules and Prune secp256k1

- [x] 1.1 Unregister and remove the obsolete `components/cJSON` submodule and `.gitmodules` from Git tracking; verify with `git submodule status`.
- [x] 1.2 Remove the nested `.git` directory and non-essential upstream files (`ci/`, `sage/`, `doc/`, `examples/`, `tools/`, `autotools-aux/`, `.github/`) from `components/secp256k1`; verify directory size and remaining files.

## 2. Vendor and Commit secp256k1

- [x] 2.1 Verify `components/secp256k1/CMakeLists.txt` and `components/secp256k1/idf_component.yml` contain correct ESP-IDF build registrations and 32-bit optimization definitions.
- [x] 2.2 Stage and commit vendored `components/secp256k1` to the main Git repository; verify with `git status` that all files are tracked cleanly without nested repo warnings.

## 3. Build & Clean-Clone Verification

- [x] 3.1 Verify firmware builds cleanly on current target using `idf.py build`.
- [x] 3.2 Verify clean-clone build by cloning repository to an isolated temporary directory and executing `idf.py build` without network or submodule initialization steps.
