"""Select test-sys jobs from the event diff; uncertainty runs the full suite."""

import json
import os
import subprocess
from pathlib import Path

BUILD_MATRIX = [
    {
        "key": "capi",
        "build-cmd": "make build-capi && make build-capi-headless && make package-capi",
        "name": "C-API",
    },
    {"key": "capi-v8", "build-cmd": "make test-capi-v8", "name": "C-API with V8"},
    {
        "key": "wasmer",
        "build-cmd": "make build-wasmer && make package-wasmer",
        "name": "Wasmer-cli binary",
    },
    {"key": "check", "build-cmd": "make check", "name": "Wasmer API (sys)"},
    {"key": "api-feats", "build-cmd": "make check-api-features", "name": "API (sys)"},
]
TEST_MATRIX = [
    {"description": "All tests", "make": "test-all"},
    {"description": "Compilers (std only)", "make": "check-compilers-only-std"},
    {"description": "VM (baremetal)", "make": "check-baremetal"},
    {"description": "Package (feature sets)", "make": "check-package-features"},
    {"description": "Wasmer-cli", "make": "test-wasmer-cli"},
    {"description": "Examples", "make": "test-examples"},
    {"description": "CLI integ. tests", "make": "test-integration-cli-ci"},
]


def git(*args):
    return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL)


def changed_paths(event_name, event):
    if event_name == "workflow_dispatch":
        raise ValueError("manual runs exercise every area")
    head = os.environ["GITHUB_SHA"]
    if event_name == "pull_request":
        base = event["pull_request"]["base"]["sha"]
        head = event["pull_request"]["head"]["sha"]
        base = git("merge-base", base, head).decode().strip()
    elif event_name == "push":
        base = event["before"]
    elif event_name == "merge_group":
        base = event["merge_group"]["base_sha"]
        head = event["merge_group"]["head_sha"]
    else:
        raise ValueError(f"unhandled event: {event_name}")
    # Missing objects (including a new branch's all-zero base) must not skip CI.
    for revision in (base, head):
        git("cat-file", "-e", f"{revision}^{{commit}}")
    return (
        git("diff", "--no-renames", "--name-only", "-z", base, head)
        .decode()
        .split("\0")[:-1]
    )


def select(paths):
    # Engine changes fan out through integration to product; kernel changes
    # enter at integration. Unknown paths deliberately retain full coverage.
    areas = set()
    for path in paths:
        if path.startswith("wlk/") or (
            path.startswith(
                (
                    "lib/wasix/",
                    "lib/napi/",
                    "lib/sdk/",
                    "lib/c-api/",
                    "lib/c-api-imports/",
                    "tests/wasixv2/",
                )
            )
            or path == "tests/wasixv2"
        ):
            areas.add("integration")
        elif (
            path.startswith(
                (
                    "lib/api/",
                    "lib/vm/",
                    "lib/compiler",
                    "lib/types/",
                    "lib/derive/",
                    "lib/middlewares/",
                    "tests/compilers/",
                    "tests/wast/",
                )
            )
            or path == "tests/wast/spec"
        ):
            areas.add("engine")
        elif path.startswith(
            (
                "lib/cli/",
                "lib/package/",
                "lib/package-sdk/",
                "lib/backend-api/",
                "lib/config/",
                "lib/cache/",
                "lib/sys-utils/",
                "tests/integration/",
                "examples/",
            )
        ):
            areas.add("product")
        elif (
            path.startswith("docs/")
            or path.endswith(".md")
            or path in ("LICENSE", "ATTRIBUTIONS")
        ):
            continue
        else:
            # Includes root manifests, toolchains, .github/, scripts/, guest/,
            # build configuration and any new area whose dependencies are unknown.
            return {"engine", "integration", "product"}
    if "engine" in areas:
        areas.add("integration")
    if "integration" in areas:
        areas.add("product")
    return areas


def outputs(areas):
    engine = "engine" in areas
    integration = "integration" in areas
    product = "product" in areas
    return {
        "engine": engine,
        "integration": integration,
        "product": product,
        "code": bool(areas),
        "build_targets": [
            target
            for target in BUILD_MATRIX
            if engine
            or target["key"]
            in (["capi", "capi-v8", "wasmer"] if integration else ["wasmer"])
        ],
        "test_stages": (
            TEST_MATRIX
            if engine
            else (
                [
                    {
                        "description": "WASIX and product tests",
                        "make": "wasix-integration",
                        "command": 'cargo test --release --locked --target "$TARGET" '
                        "-p wasixv2 -p wasixv2-exec -p wasixv2-dylink "
                        "-p wasixv2-wasix1 -p wasixv2-codegen "
                        "-p wasmer-sdk -p wasmer-c-api-imports "
                        "-p wasmer-package -p wasmer-package-sdk "
                        "-p wasmer-backend-api -p wasmer-config "
                        "-p wasmer-cache -p wasmer-sys-utils",
                    }
                ]
                if product
                else []
            )
            + [
                stage
                for stage in TEST_MATRIX
                if stage["make"]
                in (
                    "check-package-features",
                    "test-wasmer-cli",
                    "test-examples",
                    "test-integration-cli-ci",
                )
            ]
        ),
    }


def main():
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        areas = select(changed_paths(os.environ["GITHUB_EVENT_NAME"], event))
    except (KeyError, ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"Running all areas: {error}")
        areas = {"engine", "integration", "product"}
    selected = outputs(areas)
    print(json.dumps(selected, indent=2))
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.writelines(
            f"{key}={json.dumps(value, separators=(',', ':'))}\n"
            for key, value in selected.items()
        )


if __name__ == "__main__":
    main()
