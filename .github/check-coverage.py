#!/usr/bin/env python3
"""Fail unless every uncovered source line carries a `// cov:unreachable` marker.

Reads an lcov.info file (`cargo llvm-cov --lcov`) and, for each `DA:<line>,0`
record (a line with zero hits), checks the corresponding source line for the
`cov:unreachable` annotation. Any unannotated zero-hit line fails the gate.

Coverage is measured with `--workspace` because this crate's behavior is
validated by fixture-driven integration tests (real $I bytes cross-checked
against the rifiuti-vista oracle), which `--lib` does not count.
"""

import sys
from pathlib import Path

ANNOTATION = "cov:unreachable"


def main(lcov_path: str) -> int:
    current_file = None
    source_cache: dict[str, list[str]] = {}
    failures: list[str] = []

    for raw in Path(lcov_path).read_text().splitlines():
        if raw.startswith("SF:"):
            current_file = raw[3:].strip()
        elif raw.startswith("DA:") and current_file:
            line_str, _, hits = raw[3:].partition(",")
            if hits.strip() != "0":
                continue
            line_no = int(line_str)
            if current_file not in source_cache:
                try:
                    source_cache[current_file] = Path(current_file).read_text().splitlines()
                except OSError:
                    source_cache[current_file] = []
            lines = source_cache[current_file]
            text = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
            if ANNOTATION not in text:
                failures.append(f"{current_file}:{line_no}: {text.strip()}")

    if failures:
        print("Uncovered lines without a // cov:unreachable annotation:")
        for f in failures:
            print(f"  {f}")
        return 1
    print("Coverage gate passed: every uncovered line is annotated // cov:unreachable.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: check-coverage.py <lcov.info>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
