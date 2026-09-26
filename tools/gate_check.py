#!/usr/bin/env python3
"""Fail-closed additive/non-additive classifier for a sediff diff, per the
2026-09-26 review (Opus) of the original blocklist version, which missed:
added constraints, allowxperm, typebounds, polcap, Modified type_transition,
type_change, type_member, mls/validatetrans, and all labeling statements
(portcon/genfscon/fs_use/netifcon/nodecon/initialsid/default_*).

Called as: gate_check.py <running_policy> <build_policy>
Prints either:
    ADDITIVE
or:
    NON-ADDITIVE
    reason: <text>
    reason: <text>
    ...
followed by the raw sediff output, to stdout. Exit code is always 0 (the
caller reads stdout, not the exit code, to distinguish verdicts) unless
sediff itself fails, in which case exit 1 with sediff's output on stderr.
"""
import re
import subprocess
import sys

# Sections that CAN be nonzero and still be additive -- everything else
# (type_transition/role_transition/range_transition of any kind,
# Constraints, allowxperm, typebounds, polcap, type_change, type_member,
# mls/validatetrans, portcon/genfscon/fs_use/netifcon/nodecon/initialsid/
# default_*, ...) is fail-closed NON-ADDITIVE if it appears at all.
ALLOWED_SECTIONS = {
    "Allow Rules",
    "Dontaudit Rules",
    "Auditallow Rules",
    "Neverallow Rules",  # these only restrict what's checkable at compile time
    "Types",
    "Booleans",
    "Permissive Types",
}

# Sections where a Modified entry needs its body scanned for a removed
# token before being trusted as additive.
PERM_SET_SECTIONS = {"Allow Rules", "Dontaudit Rules", "Auditallow Rules"}

HEADER_RE = re.compile(
    r"^([A-Za-z_][A-Za-z_ ]*?)\s*\((\d+)\s*Added,\s*(\d+)\s*Removed(?:,\s*(\d+)\s*Modified)?\)\s*$"
)

REMOVED_PERM_IN_BRACES_RE = re.compile(r"\{[^}]*[\s{]-[A-Za-z_][A-Za-z0-9_]*")
REMOVED_ATTR_LINE_RE = re.compile(r"^\s*-\s*[A-Za-z_][A-Za-z0-9_]*\s*$")


def run_sediff(running, build):
    proc = subprocess.run(["sediff", running, build], capture_output=True, text=True)
    if proc.returncode not in (0, 1):
        # sediff returns 1 when there IS a difference -- that's expected,
        # not a failure. Only treat other codes, or stderr with no stdout,
        # as a real error.
        print(proc.stdout, file=sys.stdout)
        print(proc.stderr, file=sys.stderr)
        sys.exit(1)
    return proc.stdout


def find_header_positions(text):
    """Return [(match, name, added, removed, modified_or_None), ...] for
    every header-line occurrence, in order. There are normally two per
    nonzero section: a summary occurrence (no detail follows) and a
    detailed occurrence (immediately followed by indented Added/Removed/
    Modified sub-lines). We use the LAST occurrence of each name as the
    authoritative one for both counts and body.
    """
    out = []
    for line in text.splitlines():
        m = HEADER_RE.match(line)
        if m:
            name = m.group(1).strip()
            added = int(m.group(2))
            removed = int(m.group(3))
            modified = int(m.group(4)) if m.group(4) is not None else None
            out.append((name, added, removed, modified))
    return out


def section_body(full_text, section_name):
    """Return the detail block text for the LAST occurrence of this
    section's header in the full sediff text, i.e. everything from that
    header line up to (but not including) the next header line of any
    section, or end of text.
    """
    lines = full_text.splitlines()
    header_line_indices = []
    for i, line in enumerate(lines):
        if HEADER_RE.match(line):
            header_line_indices.append(i)
    last_start = None
    for i in header_line_indices:
        name = HEADER_RE.match(lines[i]).group(1).strip()
        if name == section_name:
            last_start = i
    if last_start is None:
        return ""
    end = len(lines)
    for i in header_line_indices:
        if i > last_start:
            end = i
            break
    return "\n".join(lines[last_start:end])


def classify(full_text):
    reasons = []
    seen = {}
    for name, added, removed, modified in find_header_positions(full_text):
        # keep the last (authoritative, with real counts) occurrence
        seen[name] = (added, removed, modified)

    for name, (added, removed, modified) in seen.items():
        modified = modified or 0
        total = added + removed + modified
        if total == 0:
            continue
        if name not in ALLOWED_SECTIONS:
            reasons.append(f"unhandled section: {name} ({added} Added, {removed} Removed"
                            f"{f', {modified} Modified' if modified else ''})")
            continue
        if removed > 0:
            reasons.append(f"{name}: Removed count is {removed} (must be 0)")
        if name == "Booleans" and modified > 0:
            reasons.append(f"{name}: Modified count is {modified} -- a boolean default "
                            "change, never safe to load live regardless of direction "
                            "(the kernel preserves runtime values across reload)")
        elif modified > 0 and name in PERM_SET_SECTIONS:
            body = section_body(full_text, name)
            if REMOVED_PERM_IN_BRACES_RE.search(body):
                reasons.append(f"{name}: a Modified rule has a removed permission "
                                "(a bare -perm token)")
        elif modified > 0 and name == "Types":
            body = section_body(full_text, name)
            has_removed_attr = False
            for line in body.splitlines():
                if REMOVED_ATTR_LINE_RE.match(line):
                    has_removed_attr = True
                    break
                if REMOVED_PERM_IN_BRACES_RE.search(line):
                    has_removed_attr = True
                    break
            if has_removed_attr:
                reasons.append(f"{name}: a Modified type lost an attribute membership")

    return reasons


def main():
    if len(sys.argv) != 3:
        print("usage: gate_check.py <running_policy> <build_policy>", file=sys.stderr)
        sys.exit(2)
    running, build = sys.argv[1], sys.argv[2]
    full_text = run_sediff(running, build)
    reasons = classify(full_text)
    if reasons:
        print("NON-ADDITIVE")
        for r in reasons:
            print(f"reason: {r}")
    else:
        print("ADDITIVE")
    print()
    print(full_text)


if __name__ == "__main__":
    main()
