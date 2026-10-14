#!/usr/bin/env python3
"""Crate layering check (T00, rules from tasks/README.md "Project-wide rules").

Reads `cargo metadata` and fails when a workspace crate breaks the dependency
direction:

* direct internal (`courier-ftp-*`) dependencies must be in the crate's allow list;
* the transitive closure of *normal* dependencies (dev/build deps ignored, all
  target platforms included) must not contain a forbidden crate;
* the local-only build (`--no-default-features`) of `courier-ftp` must not
  contain `courier-ftp-sync`, and `courier-ftp-sync` may only be an optional
  dependency of the binary (feature `sync`).

The graph is checked twice: with `--all-features` (worst case) and with
`--no-default-features` (local-only). Only the Python standard library is
used, so the script runs on any CI image with `cargo` and `python3`.

Crates listed in RULES that don't exist yet are ignored; a workspace crate
without a rule is an error.

Usage: python3 scripts/check-layering.py [--manifest-path Cargo.toml]
Exit code 0 = clean, 1 = violations, 2 = could not run cargo metadata.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

INTERNAL_PREFIX = "courier-ftp"

# Crates that put a UI on the screen or parse a command line. Only the binary may
# pull them in.
UI = {"ratatui", "ratatui-core", "crossterm", "clap"}

# Client-side crates the sync server must never link.
CLIENT = {
    "courier-ftp",
    "courier-ftp-core",
    "courier-ftp-store",
    "courier-ftp-proto-ftp",
    "courier-ftp-proto-sftp",
    "courier-ftp-sync",
}

# crate -> (allowed direct internal deps or None for "any", forbidden transitive deps)
RULES: dict[str, tuple[set[str] | None, set[str]]] = {
    # Pure crypto: no I/O runtimes, no storage, no network protocols.
    "courier-ftp-crypto": (
        set(),
        UI | {"tokio", "mio", "rusqlite", "russh", "reqwest"},
    ),
    # Sync wire types: serde only (T83), no runtime, no HTTP stack, no storage.
    "courier-ftp-proto": (
        {"courier-ftp-crypto"},
        UI | {"rusqlite", "russh", "tokio", "mio", "hyper", "axum", "reqwest"},
    ),
    "courier-ftp-core": ({"courier-ftp-crypto", "courier-ftp-proto"}, UI),
    "courier-ftp-store": ({"courier-ftp-core", "courier-ftp-crypto"}, UI),
    # Protocol crates (D5): implement core's Backend trait, nothing above it.
    "courier-ftp-proto-ftp": ({"courier-ftp-core"}, UI | {"russh", "rusqlite"}),
    "courier-ftp-proto-sftp": ({"courier-ftp-core"}, UI | {"rusqlite"}),
    "courier-ftp-sync": (
        {
            "courier-ftp-core",
            "courier-ftp-store",
            "courier-ftp-proto",
            "courier-ftp-crypto",
        },
        UI,
    ),
    "courier-ftp-server": (
        {"courier-ftp-proto", "courier-ftp-crypto"},
        UI | {"russh", "rusqlite"} | CLIENT,
    ),
    "courier-ftp-e2e": (None, set()),
    # The binary: everything client-side; courier-ftp-sync only behind feature `sync`.
    "courier-ftp": (None, {"courier-ftp-server"}),
}

# Crates that may depend on courier-ftp-sync, and only optionally (feature `sync`).
SYNC_OPTIONAL_IN = {"courier-ftp"}
LOCAL_ONLY_ROOTS = {"courier-ftp"}


def metadata(manifest: str | None, features: str) -> dict:
    cmd = ["cargo", "metadata", "--format-version", "1", "--locked", features]
    if manifest:
        cmd += ["--manifest-path", manifest]
    try:
        out = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as err:
        stderr = getattr(err, "stderr", "") or ""
        print(f"error: `{' '.join(cmd)}` failed: {err}\n{stderr}", file=sys.stderr)
        sys.exit(2)
    return json.loads(out.stdout)


def normal_graph(meta: dict) -> tuple[dict[str, str], dict[str, set[str]]]:
    """Return (package id -> name, package id -> ids of normal deps)."""
    names = {p["id"]: p["name"] for p in meta["packages"]}
    edges: dict[str, set[str]] = {}
    for node in meta["resolve"]["nodes"]:
        deps = set()
        for dep in node.get("deps", []):
            kinds = dep.get("dep_kinds") or [{"kind": None}]
            if any(k.get("kind") is None for k in kinds):
                deps.add(dep["pkg"])
        edges[node["id"]] = deps
    return names, edges


def closure(root: str, edges: dict[str, set[str]]) -> set[str]:
    seen: set[str] = set()
    stack = list(edges.get(root, ()))
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        stack.extend(edges.get(cur, ()))
    return seen


def path_to(root: str, target: str, edges: dict[str, set[str]], names) -> str:
    """Shortest dependency path root -> target, for readable errors."""
    prev = {root: None}
    queue = [root]
    while queue:
        cur = queue.pop(0)
        if cur == target:
            break
        for nxt in sorted(edges.get(cur, ())):
            if nxt not in prev:
                prev[nxt] = cur
                queue.append(nxt)
    chain = []
    cur = target
    while cur is not None and cur in prev:
        chain.append(names[cur])
        cur = prev[cur]
    return " -> ".join(reversed(chain))


def check(meta: dict, label: str, local_only: bool) -> list[str]:
    errors: list[str] = []
    names, edges = normal_graph(meta)
    members = {pid: names[pid] for pid in meta["workspace_members"]}

    for pid, name in sorted(members.items(), key=lambda kv: kv[1]):
        if name not in RULES:
            errors.append(
                f"[{label}] {name}: workspace crate has no layering rule; "
                "add it to RULES in scripts/check-layering.py"
            )
            continue
        allowed, forbidden = RULES[name]
        direct = {names[d] for d in edges.get(pid, ())}

        if allowed is not None:
            for dep in sorted(direct):
                if dep.startswith(INTERNAL_PREFIX) and dep not in allowed:
                    errors.append(
                        f"[{label}] {name} must not depend on {dep} "
                        f"(allowed internal deps: {sorted(allowed) or 'none'})"
                    )

        reach = closure(pid, edges)
        for dep_id in sorted(reach, key=lambda i: names[i]):
            if names[dep_id] in forbidden:
                errors.append(
                    f"[{label}] {name} must not (transitively) depend on "
                    f"{names[dep_id]}: {path_to(pid, dep_id, edges, names)}"
                )

        if local_only and name in LOCAL_ONLY_ROOTS:
            for dep_id in reach:
                if names[dep_id] == "courier-ftp-sync":
                    errors.append(
                        f"[{label}] local-only build of {name} links courier-ftp-sync "
                        f"(feature `sync` off): {path_to(pid, dep_id, edges, names)}"
                    )

    # courier-ftp-sync may only be an *optional* dependency of the binary.
    for pkg in meta["packages"]:
        if pkg["id"] not in members:
            continue
        for dep in pkg["dependencies"]:
            if dep["name"] != "courier-ftp-sync" or dep.get("kind") is not None:
                continue
            if pkg["name"] in SYNC_OPTIONAL_IN and not dep.get("optional"):
                errors.append(
                    f"[{label}] {pkg['name']} depends on courier-ftp-sync "
                    "unconditionally; it must be optional behind feature `sync`"
                )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest-path", default=None)
    args = parser.parse_args()

    errors: list[str] = []
    errors += check(metadata(args.manifest_path, "--all-features"), "all-features", False)
    errors += check(
        metadata(args.manifest_path, "--no-default-features"), "no-default-features", True
    )

    errors = list(dict.fromkeys(errors))  # two versions of one crate -> same message
    if errors:
        print("crate layering violations:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print("crate layering OK (all-features and no-default-features graphs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
