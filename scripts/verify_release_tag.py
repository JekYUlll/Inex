#!/usr/bin/env python3
"""Bind a release tag to the exact Cargo and VS Code package version."""

from __future__ import annotations

import argparse
import json
import re
import sys

from package_release import project_version
from release_common import REPOSITORY_ROOT, ReleaseError


def validate_release_tag(tag: str, version: str) -> None:
    if re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", tag) is None:
        raise ReleaseError("release tag must use the exact stable form vMAJOR.MINOR.PATCH")
    if tag != f"v{version}":
        raise ReleaseError(f"release tag {tag!r} does not match project version {version!r}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify package version agreement and optionally bind an exact release tag."
    )
    parser.add_argument("--tag", help="Exact Git tag to validate (required for tag-triggered runs).")
    arguments = parser.parse_args()
    version = project_version(REPOSITORY_ROOT)
    if arguments.tag is not None:
        validate_release_tag(arguments.tag, version)
    print(json.dumps({"releaseVersion": version, "tag": arguments.tag}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as error:
        print(f"verify_release_tag: {error}", file=sys.stderr)
        raise SystemExit(1) from None
