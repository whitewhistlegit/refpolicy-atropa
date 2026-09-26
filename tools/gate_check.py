#!/usr/bin/env python3
"""Fail-closed additive/non-additive classifier for a sediff diff, per the
2026-09-26 review (Opus) of the original blocklist version, which missed:
added constraints, allowxperm, typebounds, polcap, Modified type_transition,
type_change, type_member, mls/validatetrans, and all labeling statements
(portcon/genfscon/fs_use/netifcon/nodecon/initialsid/default_*).

Round 2 (same review, re-check) found two more fail-opens, both fixed here:
- sediff 4.7.1 has no "Permissive Types" section; a permissive removal shows
  up only as `* name (Removed permissive)` inside the Types body, which the
  old code never looked for.
- "Policy Properties (N Modified)" (e.g. handle_unknown allow->reject) uses
  a header format with no "Added, Removed" at all, so it was invisible to
  the old HEADER_RE and silently passed. Now parsed explicitly, and a
  catch-all flags anything sediff emits that still isn't recognized.

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

# Headers with no "Added, Removed" at all -- currently only "Policy
# Properties (N Modified)" (sediff's handle_unknown / mls / policycap
# summary), but treated generically in case sediff adds more of these.
MODIFIED_ONLY_HEADER_RE = re.compile(r"^([A-Za-z_][A-Za-z_ ]*?)\s*\((\d+)\s*Modified\)\s*$")

# Any top-level (non-indented) "Name (...)" line -- used to catch header
# formats neither of the above regexes recognize, so an unfamiliar future
# sediff section fails closed instead of being silently skipped.
HEADER_ANY_RE = re.compile(r"^([A-Za-z_][A-Za-z_ ]*?)\s*\(([^)]*)\)\s*$")

REMOVED_PERM_IN_BRACES_RE = re.compile(r"\{[^}]*[\s{]-[A-Za-z_][A-Za-z0-9_]*")
REMOVED_ATTR_LINE_RE = re.compile(r"^\s*-\s*[A-Za-z_][A-Za-z0-9_]*\s*$")
# `* name (..., Removed permissive, ...)` / `(Removed permissive)` etc. --
# any "Removed ..." token inside a Types `*`-change-line's parens, not just
# the indented `- ` sub-lines already covered above.
REMOVED_IN_STAR_LINE_RE = re.compile(r"^\s*\*\s*\S+\s*\([^)]*\bRemoved\b[^)]*\)")


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


def _match_any_header(line):
    """Try each known header format against one line. Returns
    (name, added, removed, modified, recognized) or None if the line isn't
    a header at all. `recognized` is False for a line that LOOKS like a
    header (matches HEADER_ANY_RE) but isn't one of the known formats --
    the caller fails closed on those.
    """
    m = HEADER_RE.match(line)
    if m:
        name = m.group(1).strip()
        added = int(m.group(2))
        removed = int(m.group(3))
        modified = int(m.group(4)) if m.group(4) is not None else None
        return (name, added, removed, modified, True)
    m = MODIFIED_ONLY_HEADER_RE.match(line)
    if m:
        name = m.group(1).strip()
        return (name, 0, 0, int(m.group(2)), True)
    m = HEADER_ANY_RE.match(line)
    if m:
        return (m.group(1).strip(), 0, 0, 0, False)
    return None


def find_header_positions(text):
    """Return [(name, added, removed, modified_or_None), ...] for every
    RECOGNIZED header-line occurrence, in order. There are normally two per
    nonzero section: a summary occurrence (no detail follows) and a
    detailed occurrence (immediately followed by indented Added/Removed/
    Modified sub-lines). We use the LAST occurrence of each name as the
    authoritative one for both counts and body.
    """
    out = []
    for line in text.splitlines():
        m = _match_any_header(line)
        if m and m[4]:
            out.append(m[:4])
    return out


def find_unrecognized_headers(text):
    """Return the raw text of any top-level '<Name> (...)' line that looks
    like a sediff section header but matches neither known format. Fails
    closed against future sediff output changes instead of silently
    treating them as additive.
    """
    out = []
    for line in text.splitlines():
        m = _match_any_header(line)
        if m and not m[4]:
            out.append(line.strip())
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
        m = _match_any_header(line)
        if m:
            header_line_indices.append(i)
    last_start = None
    for i in header_line_indices:
        name = _match_any_header(lines[i])[0]
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
        elif name == "Types" and total > 0:
            # sediff 4.7.1 has no separate "Permissive Types" section --
            # a permissive removal shows up only as a `* name (...Removed
            # permissive...)` line inside Types, with no `- ` sub-line and
            # no braces, so it's checked independently of `modified > 0`.
            body = section_body(full_text, name)
            has_removed_attr = False
            for line in body.splitlines():
                if REMOVED_ATTR_LINE_RE.match(line):
                    has_removed_attr = True
                    break
                if REMOVED_PERM_IN_BRACES_RE.search(line):
                    has_removed_attr = True
                    break
                if REMOVED_IN_STAR_LINE_RE.search(line):
                    has_removed_attr = True
                    break
            if has_removed_attr:
                reasons.append(f"{name}: a type lost permissive status, an attribute "
                                "membership, or an alias (a 'Removed ...' entry)")

    unrecognized = find_unrecognized_headers(full_text)
    if unrecognized:
        for line in unrecognized:
            reasons.append(f"unrecognized sediff header: {line!r}")

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
