#!/usr/bin/env python3
"""Benchmark gates and regression checks over criterion's results.

Criterion writes `target/criterion/<group>/<function>/<baseline>/estimates.json`
(times in ns) and `benchmark.json` (throughput). This script reads them; it needs
no extra tools.

    bench-gate.py gate [--local] [--dir target/criterion] [--baseline ci]
        Hard gates for the spec targets (`scripts/bench-gates.toml`). CI uses the
        CI-adjusted thresholds (2x the spec, runners are slower and noisy);
        `--local` uses the spec targets for the reference machine. A gates file
        without `[[gate]]` entries prints "no gates" and passes (each task adds
        its gate when its bench exists).

    bench-gate.py compare --old main --new ci [--threshold 15] [--dir ...]
        Every benchmark present in both baselines: fail when the new median is
        more than `threshold` percent slower (the regression alert).

    bench-gate.py self-test
        Checks the comparison logic on synthetic results: a 20% slowdown is
        flagged, a 5% one is not, a missed gate fails, CI and local thresholds
        differ, fractional `max_ms` and `min_mb_s` throughput gates work, and an
        empty gates file passes.

Baselines are saved with `cargo bench -- --save-baseline <name>`; never name one
`new` or `base` (criterion's own working directories: saving to `new` leaves empty
files).

Exit status: 0 ok, 1 a gate or regression failed, 2 usage / missing data.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATES = ROOT / "scripts" / "bench-gates.toml"


def median_ns(bench_dir: Path, baseline: str) -> float | None:
    est = bench_dir / baseline / "estimates.json"
    if not est.is_file():
        return None
    data = json.loads(est.read_text())
    return float(data["median"]["point_estimate"])


def throughput_bytes(bench_dir: Path, baseline: str) -> int | None:
    meta = bench_dir / baseline / "benchmark.json"
    if not meta.is_file():
        return None
    tp = json.loads(meta.read_text()).get("throughput") or {}
    return tp.get("Bytes") or tp.get("BytesDecimal")


def benches(root: Path, baseline: str) -> dict[str, Path]:
    """`group/function` -> its directory, for every bench with `baseline`."""
    out = {}
    for est in root.glob(f"**/{baseline}/estimates.json"):
        bench_dir = est.parent.parent
        name = bench_dir.relative_to(root).as_posix()
        if name.startswith("report") or "/report" in name:
            continue
        out[name] = bench_dir
    return out


def load_gates(gates_file: Path) -> list[dict]:
    spec = tomllib.loads(gates_file.read_text())
    gates = spec.get("gate", [])
    for g in gates:
        if "bench" not in g:
            raise SystemExit(f"{gates_file}: a [[gate]] has no `bench`")
        pairs = (("max_ms", "ci_max_ms"), ("min_mb_s", "ci_min_mb_s"))
        kinds = [p for p in pairs if p[0] in g or p[1] in g]
        if len(kinds) != 1 or not all(isinstance(g.get(k), (int, float)) for k in kinds[0]):
            raise SystemExit(
                f"{gates_file}: gate {g['bench']} needs either max_ms + ci_max_ms "
                "or min_mb_s + ci_min_mb_s (numbers)"
            )
    return gates


def gate(root: Path, baseline: str, local: bool, gates_file: Path = GATES) -> int:
    gates = load_gates(gates_file)
    if not gates:
        print(f"no gates in {gates_file.name}")
        return 0
    if not root.is_dir():
        print(f"{root} does not exist; run `cargo bench` first")
        return 2
    failed = 0
    for g in gates:
        bench_dir = root / g["bench"]
        ns = median_ns(bench_dir, baseline)
        if ns is None:
            print(f"MISSING  {g['bench']} (no {baseline} result; did the bench run?)")
            failed += 1
            continue
        if "min_mb_s" in g:
            limit = g["min_mb_s"] if local else g["ci_min_mb_s"]
            nbytes = throughput_bytes(bench_dir, baseline)
            if nbytes is None:
                print(f"MISSING  {g['bench']} has no throughput")
                failed += 1
                continue
            mb_s = nbytes / (ns / 1e9) / 1e6
            ok = mb_s >= limit
            print(f"{'ok  ' if ok else 'FAIL'}     {g['bench']}: {mb_s:.1f} MB/s (gate >= {limit})")
        else:
            limit = g["max_ms"] if local else g["ci_max_ms"]
            ms = ns / 1e6
            ok = ms <= limit
            print(f"{'ok  ' if ok else 'FAIL'}     {g['bench']}: {ms:.3f} ms (gate <= {limit})")
        failed += 0 if ok else 1
    return 1 if failed else 0


def compare(root: Path, old: str, new: str, threshold: float) -> int:
    olds, news = benches(root, old), benches(root, new)
    common = sorted(set(olds) & set(news))
    if not common:
        print(f"no benchmark has both {old!r} and {new!r} results")
        return 2
    regressed = 0
    for name in common:
        a, b = median_ns(olds[name], old), median_ns(news[name], new)
        if not a or b is None:
            continue
        change = (b - a) / a * 100
        flag = "REGRESSED" if change > threshold else "ok"
        regressed += change > threshold
        print(f"{flag:<10} {name}: {a / 1e6:.3f} ms -> {b / 1e6:.3f} ms ({change:+.1f}%)")
    if regressed:
        print(f"{regressed} benchmark(s) slower by more than {threshold}%")
    return 1 if regressed else 0


def _write(root: Path, name: str, baseline: str, ns: float, nbytes: int | None = None) -> None:
    d = root / name / baseline
    d.mkdir(parents=True, exist_ok=True)
    (d / "estimates.json").write_text(json.dumps({"median": {"point_estimate": ns}}))
    tp = {"Bytes": nbytes} if nbytes else None
    (d / "benchmark.json").write_text(json.dumps({"throughput": tp}))


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write(root, "g/fast", "main", 1_000_000)
        _write(root, "g/fast", "ci", 1_050_000)  # +5%: fine
        assert compare(root, "main", "ci", 15) == 0, "5% must pass"
        _write(root, "g/slow", "main", 1_000_000)
        _write(root, "g/slow", "ci", 1_200_000)  # +20%: deliberately slowed
        assert compare(root, "main", "ci", 15) == 1, "20% must be flagged"

        gates = root / "gates.toml"
        gates.write_text(
            '[[gate]]\nbench = "emulator_parse/x"\nmin_mb_s = 100\nci_min_mb_s = 50\n'
            '[[gate]]\nbench = "render_300x100/x"\nmax_ms = 2\nci_max_ms = 4\n'
        )
        # 1 MiB in 10 ms = 105 MB/s; render 3 ms: CI passes, local fails.
        _write(root, "emulator_parse/x", "ci", 10_000_000, 1 << 20)
        _write(root, "render_300x100/x", "ci", 3_000_000)
        assert gate(root, "ci", local=False, gates_file=gates) == 0
        assert gate(root, "ci", local=True, gates_file=gates) == 1
        _write(root, "emulator_parse/x", "ci", 40_000_000, 1 << 20)  # 26 MB/s
        assert gate(root, "ci", local=False, gates_file=gates) == 1

        # Fractional max_ms (queue/next_runnable_100k) and a throughput gate.
        gates.write_text(
            '[[gate]]\nbench = "queue/next_runnable_100k"\nmax_ms = 0.02\nci_max_ms = 0.04\n'
            '[[gate]]\nbench = "transfer_engine/mock_single_stream_1gib"\n'
            "min_mb_s = 1000\nci_min_mb_s = 500\n"
        )
        _write(root, "queue/next_runnable_100k", "ci", 30_000)  # 0.03 ms
        # 1 GiB in 1.5 s = 716 MB/s: CI (>= 500) passes, local (>= 1000) fails.
        _write(root, "transfer_engine/mock_single_stream_1gib", "ci", 1_500_000_000, 1 << 30)
        assert gate(root, "ci", local=False, gates_file=gates) == 0
        assert gate(root, "ci", local=True, gates_file=gates) == 1
        _write(root, "queue/next_runnable_100k", "ci", 50_000)  # 0.05 ms > 0.04
        assert gate(root, "ci", local=False, gates_file=gates) == 1

        # An empty gates file passes, even without any criterion output.
        empty = root / "empty.toml"
        empty.write_text("# no gates yet\n")
        assert gate(root / "missing", "ci", local=False, gates_file=empty) == 0
        # The shipped gates file parses.
        load_gates(GATES)
    print("self-test ok")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gate")
    g.add_argument("--local", action="store_true")
    g.add_argument("--dir", type=Path, default=ROOT / "target" / "criterion")
    g.add_argument("--baseline", default="ci")
    c = sub.add_parser("compare")
    c.add_argument("--old", required=True)
    c.add_argument("--new", default="ci")
    c.add_argument("--threshold", type=float, default=15.0)
    c.add_argument("--dir", type=Path, default=ROOT / "target" / "criterion")
    sub.add_parser("self-test")
    a = p.parse_args()
    if a.cmd == "self-test":
        return self_test()
    if a.cmd == "gate":
        return gate(a.dir, a.baseline, a.local)
    if not a.dir.is_dir():
        print(f"{a.dir} does not exist; run `cargo bench` first")
        return 2
    return compare(a.dir, a.old, a.new, a.threshold)


if __name__ == "__main__":
    sys.exit(main())
