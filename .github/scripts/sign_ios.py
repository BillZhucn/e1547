#!/usr/bin/env python3
"""Ad-hoc sign iOS code inside out, without certificates or third-party packages.

Resource-only bundles are sealed by their enclosing code bundle. Discover Mach-O
files throughout the app, including native assets outside Frameworks. SideStore
or AltStore must still re-sign this test app for the user's device.
"""

import argparse
from pathlib import Path
import plistlib
import shutil
import subprocess


def run(*args):
    print("+", " ".join(map(str, args)), flush=True)
    subprocess.run(args, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    app = args.app.resolve(strict=True)
    if not app.is_dir() or app.suffix != ".app":
        raise ValueError(f"Expected an app bundle: {app}")

    paths = sorted(app.rglob("*"))
    binaries = set()
    # Thin 32/64-bit and universal Mach-O magic, in either byte order.
    magic = {bytes.fromhex(value) for value in (
        "feedface", "cefaedfe", "feedfacf", "cffaedfe",
        "cafebabe", "bebafeca", "cafebabf", "bfbafeca",
    )}
    print("::group::Mach-O inventory (entire app)", flush=True)
    for path in paths:
        if path.is_symlink() or not path.is_file():
            continue
        with path.open("rb") as stream:
            if stream.read(4) not in magic:
                continue
        description = subprocess.check_output(["file", "-b", str(path)], text=True).strip()
        if "Mach-O" in description:
            print(f"{path.relative_to(app)}: {description}", flush=True)
            binaries.add(path)
    print("::endgroup::", flush=True)

    targets = set(binaries)
    print("::group::Bundle inventory", flush=True)
    for bundle in [app, *paths]:
        if bundle.is_symlink() or not bundle.is_dir():
            continue
        if bundle.suffix not in {".app", ".appex", ".framework", ".bundle", ".xpc"}:
            continue
        plist = bundle / "Info.plist"
        info = plistlib.loads(plist.read_bytes()) if plist.is_file() else {}
        executable = info.get("CFBundleExecutable")
        print(f"{bundle.relative_to(app)}: executable={executable or '(resource only)'}", flush=True)
        if executable:
            binary = (bundle / executable).resolve(strict=True)
            if binary not in binaries:
                raise ValueError(f"Bundle executable is not a discovered Mach-O: {binary}")
            targets.discard(binary)  # Sign its bundle, not the same executable twice.
            targets.add(bundle)
        elif bundle.suffix != ".bundle":
            raise ValueError(f"Missing CFBundleExecutable: {bundle}")
    print("::endgroup::", flush=True)
    if app not in targets:
        raise ValueError("Runner.app was not discovered as executable code")

    # Depth first, with a stable path tie-breaker; the root app is always last.
    ordered = sorted(targets, key=lambda path: (-len(path.parts), str(path)))
    if not args.verify_only:
        print("::group::Existing signatures (unsigned code is expected)", flush=True)
        for target in ordered:
            print(f"Inspecting {target.relative_to(app)}", flush=True)
            subprocess.run(["codesign", "--display", "--verbose=2", str(target)], check=False)
        print("::endgroup::", flush=True)

        # Remove resource seals before changing any executable signatures.
        for path in sorted(paths, key=lambda path: (-len(path.parts), str(path))):
            if path.name == "_CodeSignature" and path.is_dir() and not path.is_symlink():
                print(f"Removing stale seal: {path.relative_to(app)}", flush=True)
                shutil.rmtree(path)
        for target in ordered:
            run("codesign", "--force", "--sign", "-", "--timestamp=none", str(target))

    print("::group::Verify all executable code and bundles", flush=True)
    for target in sorted(targets | binaries, key=lambda path: (-len(path.parts), str(path))):
        run("codesign", "--verify", "--strict", "--all-architectures", "--verbose=2", str(target))
    # --deep is an additional verification check, never the signing strategy.
    run("codesign", "--verify", "--deep", "--strict", "--all-architectures", "--verbose=2", str(app))
    run("codesign", "--display", "--verbose=2", str(app))
    print(f"Verified {len(binaries)} Mach-O files and {len(targets)} signing targets.", flush=True)
    print("::endgroup::", flush=True)


if __name__ == "__main__":
    main()
