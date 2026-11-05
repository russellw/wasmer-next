#!/usr/bin/env python3
"""Reject direct Wasmer runtime dependencies in any WLK workspace package."""
import json
import subprocess
import sys

metadata = subprocess.run(
    ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"],
    check=True,
    capture_output=True,
    text=True,
)
packages = json.loads(metadata.stdout)["packages"]
violations = []
for package in packages:
    for dependency in package["dependencies"]:
        names = {dependency["name"], dependency.get("rename") or ""}
        if any(name == "wasmer" or name.startswith("wasmer-") for name in names):
            violations.append(f"{package['name']} -> {dependency['name']}")

if violations:
    print("WLK packages must not depend on Wasmer:", file=sys.stderr)
    print("\n".join(violations), file=sys.stderr)
    sys.exit(1)

print(f"checked {len(packages)} workspace packages: no direct Wasmer dependencies")
