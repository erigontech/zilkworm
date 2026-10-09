#!/usr/bin/env python3
# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

"""Query the ERE dependencies resolved by a zkevm-benchmark-workload checkout.

Usage:
    tools/ere_workload.py <workload-dir> sp1-sdk-version
    tools/ere_workload.py <workload-dir> reth-artifact-url

sp1-sdk-version     SP1 SDK version ere-hosts appends to guest artifact names
                    (stateless-validator-<client>-sp1-<version>.elf), resolved as
                    ere-catalog's build script does: the sp1-verifier dependency of
                    ere-verifier-sp1 in the ere workspace lockfile.
reth-artifact-url   Base URL of the reth sp1 guest artifacts, from the
                    artifact-registry.json embedded by the resolved
                    stateless-validator-downloader.
"""
import json
import os
import subprocess
import sys
import tomllib


def _manifest_dir(meta, name):
    paths = [p["manifest_path"] for p in meta["packages"] if p["name"] == name]
    if len(paths) != 1:
        sys.exit(f"expected one {name} package in the workload graph, found {len(paths)}")
    return os.path.dirname(paths[0])


def _resolve_version(pkg):
    """Mirror of ere_util_build::resolve_pkg_version."""
    source = pkg.get("source", "")
    if source.startswith("git+") and "#" in source:
        repr_, rev = source[len("git+"):].split("#", 1)
        return repr_.split("?tag=", 1)[1] if "?tag=" in repr_ else rev[:7]
    return f"v{pkg['version']}"


def sp1_sdk_version(meta):
    root = _manifest_dir(meta, "ere-catalog")
    while not os.path.exists(os.path.join(root, "Cargo.lock")):
        if os.path.dirname(root) == root:
            sys.exit("no Cargo.lock above ere-catalog")
        root = os.path.dirname(root)
    with open(os.path.join(root, "Cargo.lock"), "rb") as f:
        packages = tomllib.load(f)["package"]
    crate = next(p for p in packages if p["name"] == "ere-verifier-sp1")
    # Lockfile dependency entries are "name", "name version" or "name version (source)".
    deps = [d.split(" ", 2) for d in crate.get("dependencies", []) if d.split(" ", 1)[0] == "sp1-verifier"]
    if len(deps) != 1:
        sys.exit(f"expected one sp1-verifier dependency of ere-verifier-sp1, found {len(deps)}")
    dep = deps[0]
    matches = [
        p for p in packages
        if p["name"] == "sp1-verifier"
        and (len(dep) < 2 or p["version"] == dep[1])
        and (len(dep) < 3 or p.get("source", "") == dep[2].strip("()"))
    ]
    if len(matches) != 1:
        sys.exit(f"expected one sp1-verifier package for {' '.join(dep)}, found {len(matches)}")
    return _resolve_version(matches[0])


def reth_artifact_url(meta):
    registry = os.path.join(_manifest_dir(meta, "stateless-validator-downloader"), "..", "..", "artifact-registry.json")
    with open(registry) as f:
        validators = json.load(f)["stateless_validators"]
    return next(
        os.path.dirname(a["elf_url"])
        for g in validators if g["name"] == "reth"
        for a in g["artifacts"] if a["zkvm"] == "sp1"
    )


QUERIES = {"sp1-sdk-version": sp1_sdk_version, "reth-artifact-url": reth_artifact_url}


def main():
    if len(sys.argv) != 3 or sys.argv[2] not in QUERIES:
        sys.exit(f"usage: {sys.argv[0]} <workload-dir> {{{'|'.join(QUERIES)}}}")
    meta = json.loads(subprocess.run(
        ["cargo", "metadata", "--format-version", "1"],
        cwd=sys.argv[1], check=True, stdout=subprocess.PIPE,
    ).stdout)
    print(QUERIES[sys.argv[2]](meta))


if __name__ == "__main__":
    main()
