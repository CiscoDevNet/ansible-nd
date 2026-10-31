#!/usr/bin/env python3
"""Read-only gate: integration execution must use unmodified selected-branch sources."""

import argparse
import hashlib
from pathlib import Path
import re
import subprocess


# These exact files are written by the original develop preparation tasks. They
# are data payloads, not authored tests, and their targets do not ignore them.
GENERATED_CONFIG_FILES = {
    "tests/integration/targets/%s/files/%s_%s_conf.yaml" % (target, target, name)
    for target, names in (
        ("nd_manage_switches", ("base", "merge", "replaced", "overridden", "rma", "sanity", "poap")),
        ("nd_vpc_pair", ("gather_setup", "delete_setup", "override_initial", "override_overridden",
                         "replace_initial", "replace_replaced", "merge_full", "merge_modified",
                         "merge_minimal", "merge_no_deploy")),
    )
    for name in names
}


def regular_output(root, relative):
    path = root / relative
    if not path.is_file() or path.is_symlink():
        return False
    return not any(parent.is_symlink() for parent in path.parents if parent != root and root in parent.parents)


def generated_config_output(root, relative, allowed=None):
    return relative in (GENERATED_CONFIG_FILES if allowed is None else allowed) and regular_output(root, relative)


def generated_python_cache(root, relative, tracked):
    path = Path(relative)
    match = re.fullmatch(r"(.+)\.cpython-\d+(?:\.opt-\d+)?\.pyc", path.name)
    source = str(path.parent.parent / (match[1] + ".py")) if match else ""
    return path.parent.name == "__pycache__" and source in tracked and regular_output(root, relative)


def verify(collection_root, expected_commit, expected_branch="develop"):
    root = Path(collection_root).resolve()

    def git(*args):
        return subprocess.check_output(["git", "-C", str(root), *args], text=True, stderr=subprocess.DEVNULL).strip()

    if not isinstance(expected_branch, str) or not expected_branch:
        raise ValueError("expected collection branch must be a valid nonempty branch name")
    try:
        branch_name = git("check-ref-format", "--branch", expected_branch)
    except subprocess.CalledProcessError:
        raise ValueError("expected collection branch must be a valid nonempty branch name") from None
    # --branch can expand checkout shorthand such as @{-1}; require the literal
    # branch selected by the pipeline, rather than accepting a local alias.
    if branch_name != expected_branch:
        raise ValueError("expected collection branch must be a literal branch name")
    try:
        actual_branch = git("symbolic-ref", "--quiet", "--short", "HEAD")
    except subprocess.CalledProcessError:
        raise ValueError("collection checkout must be on the selected branch, not detached") from None
    if actual_branch != expected_branch:
        raise ValueError("collection checkout differs from the selected branch")
    commit = git("rev-parse", "--verify", "HEAD")
    if not expected_commit or commit != expected_commit:
        raise ValueError("collection commit differs from the verified selected-branch checkout")
    changed = git("diff", "--name-only", "HEAD", "--", "plugins", "tests/integration")
    if changed:
        raise ValueError("tracked collection or integration sources were modified")
    tracked, allowed = set(), set(GENERATED_CONFIG_FILES)
    entries = git("ls-tree", "-r", "-z", commit, "--", "plugins", "tests/integration").split("\0")
    for entry in filter(None, entries):
        metadata, relative = entry.split("\t", 1)
        mode, kind, object_id = metadata.split()
        path = root / relative
        if kind != "blob" or mode not in {"100644", "100755"} or not regular_output(root, relative):
            raise ValueError("tracked collection source was removed or replaced")
        data = path.read_bytes()
        digest = hashlib.new("sha1" if len(object_id) == 40 else "sha256")
        digest.update(b"blob " + str(len(data)).encode("ascii") + b"\0" + data)
        if digest.hexdigest() != object_id:
            raise ValueError("tracked collection or integration sources were modified")
        tracked.add(relative)
        # These two original targets already ignore their generated payloads.
        # Derive their exact filenames only from the now-verified source bytes.
        for target, prefix in (("nd_manage_vrfs", "nd_vrf"), ("nd_manage_networks", "nd_network")):
            base = "tests/integration/targets/" + target + "/"
            if relative.startswith(base) and relative.endswith((".yaml", ".yml")):
                for name in re.findall(rb"(?m)^\s+file:\s*([a-z0-9_]+)\s*$", data):
                    allowed.add(base + "files/" + prefix + "_" + name.decode("ascii") + "_conf.yaml")
    # Do not trust local/global ignore rules to hide additional executable tests
    # or plugins. Permit only known generated data and caches of tracked Python.
    extra = git("ls-files", "--others", "-z", "--", "plugins", "tests/integration").split("\0")
    if any(not generated_config_output(root, name, allowed) and not generated_python_cache(root, name, tracked)
           for name in filter(None, extra)):
        raise ValueError("untracked collection or integration sources were added")
    return commit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collection-root", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-branch", default="develop")
    args = parser.parse_args()
    try:
        commit = verify(args.collection_root, args.expected_commit, args.expected_branch)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        # Do not print Git output, file contents or remote URLs.
        print("NDP_DEVELOP_SOURCE_CHECK_FAILED: " + (str(error) if isinstance(error, ValueError) else type(error).__name__))
        return 1
    print("NDP_DEVELOP_SOURCES_VERIFIED: " + args.expected_branch + " " + commit + "; no source patches")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
