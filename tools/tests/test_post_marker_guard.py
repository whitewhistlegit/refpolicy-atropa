#!/usr/bin/env python3
"""Regression test for check_bash.py's post-marker Enforcing guard (S7,
Opus's 2026-09-26 review of store-sync-apply). Can't use the marker path
on the real system for this -- creating it would change the hook's real
behavior for every session while the test runs. Instead: import the
module directly and monkeypatch its MARKER constant to a throwaway temp
file, so nothing about the real system's store-sync state is touched.

Usage: test_post_marker_guard.py <path/to/check_bash.py>
"""
import importlib.util
import io
import json
import os
import sys
import tempfile


def load_module(path):
    spec = importlib.util.spec_from_file_location("check_bash_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run(mod, cmd, enforcing):
    mod.is_enforcing = lambda: enforcing
    mod.gate_says_additive_and_current = lambda: False
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}})
    old_stdin = sys.stdin
    sys.stdin = io.StringIO(payload)
    try:
        mod.main()
        code = 0
    except SystemExit as e:
        code = e.code or 0
    finally:
        sys.stdin = old_stdin
    return "DENY" if code == 2 else "allow"


CASES = [
    # (command, enforcing, expected)
    ("sudo semodule -i foo.pp", True, "DENY"),
    ("sudo semodule -i foo.pp -N", True, "allow"),
    ("sudo semodule -i foo.pp", False, "allow"),
    ("sudo setsebool -P allow_execmod on", True, "DENY"),
    ("sudo setsebool -P allow_execmod on -N", True, "allow"),
    ("sudo semanage boolean -D", True, "DENY"),
    ("sudo semanage boolean -D -N", True, "allow"),
    ("semodule -l", True, "allow"),
    ("semodule -lfull", True, "allow"),
    ("sudo semodule -E foo", True, "allow"),
    ("sudo semodule --extract=foo", True, "allow"),
    ("sudo semodule -m -l", True, "allow"),
]


def main():
    if len(sys.argv) != 2:
        print("usage: test_post_marker_guard.py <path/to/check_bash.py>", file=sys.stderr)
        sys.exit(2)
    mod = load_module(sys.argv[1])

    with tempfile.NamedTemporaryFile(delete=False) as tmp_marker:
        marker_path = tmp_marker.name
    mod.MARKER = marker_path  # simulate a synced store WITHOUT touching the real marker

    fail = 0
    try:
        for cmd, enforcing, expected in CASES:
            got = run(mod, cmd, enforcing)
            ok = "PASS" if got == expected else "FAIL"
            if ok == "FAIL":
                fail = 1
            print(f"{ok:4} exp={expected:6} got={got:6} enforcing={str(enforcing):5} cmd={cmd}")
    finally:
        os.unlink(marker_path)

    sys.exit(fail)


if __name__ == "__main__":
    main()
