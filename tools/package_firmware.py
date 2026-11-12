#!/usr/bin/env python3
"""
nesigner multi-target firmware build and packaging tool.

Builds and packages firmware for supported ESP32 target architectures,
producing isolated release binaries, merged full-image binaries, and a web flasher manifest.
"""

import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

SUPPORTED_TARGETS = [
    "esp32s3",
    "esp32s2",
    "esp32c3",
    "esp32c5",
    "esp32c6",
    "esp32p4",
    "esp32s31",
]

TARGET_METADATA = {
    "esp32s3": {
        "chip_family": "ESP32-S3",
        "description": "Xtensa Dual-core, TinyUSB CDC-ACM (Default)",
        "transport": "TinyUSB CDC-ACM",
    },
    "esp32s2": {
        "chip_family": "ESP32-S2",
        "description": "Xtensa Single-core, TinyUSB CDC-ACM",
        "transport": "TinyUSB CDC-ACM",
    },
    "esp32c3": {
        "chip_family": "ESP32-C3",
        "description": "RISC-V Single-core, Native USB Serial/JTAG",
        "transport": "USB Serial/JTAG",
    },
    "esp32c5": {
        "chip_family": "ESP32-C5",
        "description": "RISC-V Single-core, Native USB Serial/JTAG (Wi-Fi 6)",
        "transport": "USB Serial/JTAG",
    },
    "esp32c6": {
        "chip_family": "ESP32-C6",
        "description": "RISC-V Single-core, Native USB Serial/JTAG (Wi-Fi 6 / 802.15.4)",
        "transport": "USB Serial/JTAG",
    },
    "esp32p4": {
        "chip_family": "ESP32-P4",
        "description": "RISC-V Dual-core High Performance, High-Speed TinyUSB",
        "transport": "TinyUSB High-Speed",
    },
    "esp32s31": {
        "chip_family": "ESP32-S31",
        "description": "RISC-V Dual-core 320MHz, High-Speed TinyUSB",
        "transport": "TinyUSB High-Speed",
    },
}


def get_repo_root() -> Path:
    """Return the absolute path of the repository root."""
    return Path(__file__).resolve().parent.parent


def get_version(repo_root: Path, requested_version: Optional[str] = None) -> str:
    """Detect current firmware version from git or fallback to default."""
    if requested_version:
        return requested_version.lstrip("v")

    try:
        res = subprocess.run(
            ["git", "describe", "--tags", "--always"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        tag = res.stdout.strip().lstrip("v")
        if tag:
            return tag
    except Exception:
        pass

    return "0.3.0"


def verify_environment(package_only: bool = False) -> None:
    """
    Verify ESP-IDF and build tools availability.
    Raises SystemExit with actionable advice if prerequisites are missing.
    """
    missing = []

    if not package_only:
        if not shutil.which("idf.py"):
            missing.append("idf.py")

    esptool_found = bool(shutil.which("esptool.py"))
    if not esptool_found:
        # Check if esptool can be called via python
        try:
            subprocess.run(
                [sys.executable, "-m", "esptool", "version"],
                capture_output=True,
                check=True,
            )
            esptool_found = True
        except Exception:
            esptool_found = False

    if not esptool_found:
        missing.append("esptool.py")

    if missing:
        idf_path = os.environ.get("IDF_PATH", "")
        hint_lines = [
            f"Error: Missing required build tool(s): {', '.join(missing)}.",
            "",
            "Please activate your ESP-IDF environment before running this script:",
        ]
        if idf_path and os.path.isfile(os.path.join(idf_path, "export.sh")):
            hint_lines.append(f"  . {idf_path}/export.sh")
        else:
            hint_lines.append("  . $HOME/esp/v6.1/esp-idf/export.sh  (or your installed IDF path)")
        hint_lines.append("")
        print("\n".join(hint_lines), file=sys.stderr)
        sys.exit(1)


def parse_flasher_args(build_dir: Path) -> Dict[str, Any]:
    """Parse build_<target>/flasher_args.json and extract flash settings and file offsets."""
    flasher_args_path = build_dir / "flasher_args.json"
    if not flasher_args_path.is_file():
        raise FileNotFoundError(f"flasher_args.json not found in {build_dir}")

    with open(flasher_args_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return data


def build_target(repo_root: Path, target: str, build_dir: Path, clean: bool = False, verbose: bool = False) -> None:
    """Run idf.py set-target and build for a specific target in an isolated build directory."""
    print(f"\n==========================================")
    print(f"Building firmware for target: {target}")
    print(f"Build directory: {build_dir}")
    print(f"==========================================")

    if clean and build_dir.exists():
        print(f"Cleaning build directory: {build_dir}")
        shutil.rmtree(build_dir)

    build_dir.mkdir(parents=True, exist_ok=True)

    target_sdkconfig = build_dir / "sdkconfig"

    stdout_mode = None if verbose else subprocess.PIPE
    stderr_mode = None if verbose else subprocess.PIPE

    # Check if target already set and configured in build directory
    cmake_cache = build_dir / "CMakeCache.txt"
    needs_set_target = True
    if cmake_cache.is_file() and target_sdkconfig.is_file():
        try:
            with open(cmake_cache, "r", encoding="utf-8", errors="ignore") as f:
                cache_content = f.read()
            with open(target_sdkconfig, "r", encoding="utf-8", errors="ignore") as f:
                sdkconfig_content = f.read()

            if (
                f'IDF_TARGET:STRING={target}' in cache_content
                and f'CONFIG_IDF_TARGET="{target}"' in sdkconfig_content
            ):
                needs_set_target = False
        except Exception:
            needs_set_target = True

    if needs_set_target:
        print(f"Setting IDF target to {target} (isolated sdkconfig: {target_sdkconfig})...")
        set_target_cmd = [
            "idf.py",
            "--preview",
            "-B", str(build_dir),
            "-D", f"SDKCONFIG={target_sdkconfig}",
            "set-target", target,
        ]
        proc = subprocess.run(set_target_cmd, cwd=repo_root, stdout=stdout_mode, stderr=stderr_mode, text=True)
        if proc.returncode != 0:
            if not verbose and proc.stderr:
                print(proc.stderr, file=sys.stderr)
            raise RuntimeError(f"idf.py set-target {target} failed with exit code {proc.returncode}")

    print(f"Compiling {target}...")
    build_cmd = [
        "idf.py",
        "--preview",
        "-B", str(build_dir),
        "-D", f"SDKCONFIG={target_sdkconfig}",
        "build",
    ]
    proc = subprocess.run(build_cmd, cwd=repo_root, stdout=stdout_mode, stderr=stderr_mode, text=True)
    if proc.returncode != 0:
        if not verbose and proc.stderr:
            print(proc.stderr, file=sys.stderr)
        raise RuntimeError(f"idf.py build for {target} failed with exit code {proc.returncode}")

    print(f"✓ Target {target} build succeeded.")


def merge_binary(
    repo_root: Path,
    target: str,
    flasher_args: Dict[str, Any],
    build_dir: Path,
    output_merged_bin: Path,
) -> None:
    """Use esptool.py merge_bin to produce a unified binary image at offset 0x0."""
    flash_settings = flasher_args.get("flash_settings", {})
    flash_mode = flash_settings.get("flash_mode", "dio")
    flash_size = flash_settings.get("flash_size", "2MB")
    flash_freq = flash_settings.get("flash_freq", "80m")

    flash_files = flasher_args.get("flash_files", {})
    if not flash_files:
        raise ValueError(f"No flash_files defined in flasher_args for target {target}")

    cmd = []
    if shutil.which("esptool.py"):
        cmd.append("esptool.py")
    else:
        cmd.extend([sys.executable, "-m", "esptool"])

    cmd.extend([
        "--chip", target,
        "merge_bin",
        "-o", str(output_merged_bin),
        "--flash_mode", flash_mode,
        "--flash_size", flash_size,
        "--flash_freq", flash_freq,
    ])

    for offset, rel_path in sorted(flash_files.items(), key=lambda item: int(item[0], 16)):
        bin_path = build_dir / rel_path
        if not bin_path.is_file():
            raise FileNotFoundError(f"Binary file not found: {bin_path}")
        cmd.extend([offset, str(bin_path)])

    proc = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        raise RuntimeError(f"esptool.py merge_bin failed for {target} with exit code {proc.returncode}")


def package_target(
    repo_root: Path,
    target: str,
    build_dir: Path,
    target_out_dir: Path,
) -> Dict[str, Any]:
    """Copy split binaries, generate merged binary, and return target manifest entry."""
    target_out_dir.mkdir(parents=True, exist_ok=True)
    flasher_args = parse_flasher_args(build_dir)

    flash_settings = flasher_args.get("flash_settings", {})
    flash_files = flasher_args.get("flash_files", {})

    parts = []
    # Copy split files
    for offset, rel_path in sorted(flash_files.items(), key=lambda item: int(item[0], 16)):
        src_bin = build_dir / rel_path
        dest_filename = Path(rel_path).name
        dest_bin = target_out_dir / dest_filename
        shutil.copy2(src_bin, dest_bin)

        part_name = dest_filename.replace(".bin", "")
        parts.append({
            "name": part_name,
            "filename": dest_filename,
            "path": f"{target}/{dest_filename}",
            "offset": offset,
            "size": dest_bin.stat().st_size,
        })

    # Save flasher_args.json copy
    shutil.copy2(build_dir / "flasher_args.json", target_out_dir / "flasher_args.json")

    # Generate merged binary
    merged_bin_name = "nesigner_merged.bin"
    merged_bin_path = target_out_dir / merged_bin_name
    print(f"Generating merged binary for {target} -> {merged_bin_name}...")
    merge_binary(repo_root, target, flasher_args, build_dir, merged_bin_path)

    metadata = TARGET_METADATA.get(target, {
        "chip_family": target.upper(),
        "description": target,
        "transport": "Unknown",
    })

    return {
        "target": target,
        "chip_family": metadata["chip_family"],
        "description": metadata["description"],
        "transport": metadata["transport"],
        "merged_binary": f"{target}/{merged_bin_name}",
        "merged_offset": "0x0",
        "merged_size": merged_bin_path.stat().st_size,
        "flash_settings": flash_settings,
        "parts": parts,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="nesigner multi-target firmware build and packaging tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Build and package all supported targets:
    python3 tools/package_firmware.py --all

  Build specific targets:
    python3 tools/package_firmware.py --target esp32s3 esp32c3

  Package already built targets without recompiling:
    python3 tools/package_firmware.py --target esp32s3 --package-only

  Specify custom output directory and version:
    python3 tools/package_firmware.py --all --output-dir dist --version 0.3.0
""",
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--all",
        action="store_true",
        help="Build and package all supported targets (%s)" % ", ".join(SUPPORTED_TARGETS),
    )
    group.add_argument(
        "--target",
        "-t",
        nargs="+",
        choices=SUPPORTED_TARGETS,
        help="Specify one or more targets to build and package",
    )

    parser.add_argument(
        "--output-dir",
        "-o",
        type=str,
        default="dist",
        help="Root output directory (default: 'dist')",
    )
    parser.add_argument(
        "--build-batch-dir",
        type=str,
        default="build_batch",
        help="Root directory for batch build artifacts (default: 'build_batch')",
    )
    parser.add_argument(
        "--version",
        "-v",
        type=str,
        default=None,
        help="Release version string (default: auto-detected via git describe)",
    )
    parser.add_argument(
        "--package-only",
        action="store_true",
        help="Skip compilation and package existing build directories",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Perform a clean build for the specified targets",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print verbose build command output",
    )

    args = parser.parse_args()

    repo_root = get_repo_root()
    targets = SUPPORTED_TARGETS if args.all else args.target
    version = get_version(repo_root, args.version)
    out_root = Path(args.output_dir) if os.path.isabs(args.output_dir) else repo_root / args.output_dir
    version_dir = out_root / f"v{version}"
    batch_root = Path(args.build_batch_dir) if os.path.isabs(args.build_batch_dir) else repo_root / args.build_batch_dir

    print(f"nesigner Firmware Packaging Tool")
    print(f"================================")
    print(f"Repository Root : {repo_root}")
    print(f"Version         : v{version}")
    print(f"Batch Build Dir : {batch_root}")
    print(f"Output Directory: {version_dir}")
    print(f"Targets Selected: {', '.join(targets)}")
    print(f"Mode            : {'Package only' if args.package_only else 'Build and package'}")

    verify_environment(package_only=args.package_only)

    version_dir.mkdir(parents=True, exist_ok=True)
    target_manifests = []

    for target in targets:
        # Check if batch build directory exists, fallback to build if build/flasher_args.json matches target
        build_dir = batch_root / target
        if not build_dir.exists() and args.package_only:
            default_build = repo_root / "build"
            if default_build.exists() and (default_build / "flasher_args.json").is_file():
                try:
                    fargs = parse_flasher_args(default_build)
                    if fargs.get("extra_esptool_args", {}).get("chip") == target:
                        build_dir = default_build
                except Exception:
                    pass

        if not args.package_only:
            build_target(repo_root, target, build_dir, clean=args.clean, verbose=args.verbose)
        else:
            if not build_dir.exists() or not (build_dir / "flasher_args.json").is_file():
                print(f"Error: Build directory not found for target {target}: {build_dir}", file=sys.stderr)
                print(f"Please run without --package-only to compile first.", file=sys.stderr)
                sys.exit(1)

        target_out_dir = version_dir / target
        manifest_entry = package_target(repo_root, target, build_dir, target_out_dir)
        target_manifests.append(manifest_entry)
        print(f"✓ Packaged {target} successfully.")

    manifest_file = version_dir / "manifest.json"

    # Merge with existing manifest entries if present
    existing_targets_map = {}
    if manifest_file.is_file():
        try:
            with open(manifest_file, "r", encoding="utf-8") as f:
                old_manifest = json.load(f)
                for t in old_manifest.get("targets", []):
                    existing_targets_map[t["target"]] = t
        except Exception:
            pass

    for t in target_manifests:
        existing_targets_map[t["target"]] = t

    merged_targets = [
        existing_targets_map[t]
        for t in SUPPORTED_TARGETS
        if t in existing_targets_map
    ]
    for k, v in existing_targets_map.items():
        if v not in merged_targets:
            merged_targets.append(v)

    # Write unified manifest.json
    manifest = {
        "project": "nesigner",
        "version": version,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "targets": merged_targets,
    }

    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    print(f"\n==========================================")
    print(f"All targets successfully packaged!")
    print(f"Manifest written to: {manifest_file}")
    print(f"Release files available in: {version_dir}")
    print(f"==========================================")


if __name__ == "__main__":
    main()
