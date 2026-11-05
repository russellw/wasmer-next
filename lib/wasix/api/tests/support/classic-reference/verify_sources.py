"""Verify the retained, licensed original-reference source profile without compiling it."""
import hashlib
import json
from pathlib import Path

support = Path(__file__).resolve().parent.parent
manifest = json.loads((Path(__file__).parent / "SOURCES.json").read_text())
for entry in manifest["files"]:
    path = support / entry["fixture"]
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != entry["sha256_fixture"]:
        raise SystemExit(f"reference source changed: {path}")
print(f"verified {len(manifest['files'])} retained reference source files")
