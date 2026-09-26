#!/usr/bin/env python3
"""V2 classifier for store-sync-dryrun: is a sediff between the CURRENTLY
INSTALLED (monolithic checkpolicy) policy.35 and the DRY-RUN (modular CIL)
policy.35 exactly the expected representation residue, per Opus's
2026-09-26 review-store-sync-design.md, and nothing else?

This is NOT gate_check.py and does not answer the same question. gate_check
asks "is this safe to load live without a reboot" (additive-only). This
script asks "did the store-sync dry run reproduce the SAME policy in a
different build path, plus only the known, understood differences between
checkpolicy's and CIL's representations" -- a real difference here means
the sync would change enforced behavior, which is exactly what must NOT
happen (the whole point of syncing is to reproduce the running policy).

Round 2 (Opus ran store-sync-dryrun themselves, found the classifier's
verdict was wrong on a semantic PASS -- K1-K4 below):
- K1: a "Modified Types: N" sub-header line inside the Types body was
  flagged as unexpected content. It's just a count summary, not a change.
- K2: "Type_transition Rules" had no handling at all -- any nonzero count
  fell through to "unhandled section", even the one known-expected rule.
- K3 (fail-open): the Types section's own Added/Removed header counts were
  never checked, and a bare "+ name"/"- name" line was accepted as an
  attribute change regardless of context -- a real added or removed TYPE
  (not just an attribute) would have passed silently.
- K4 (fail-open): added Type Attributes appear in sediff as "+ name" lines
  under an "Added Type Attributes:" sub-header, not as "* name (...)"
  lines -- the old *_typeattr_N check was scanning for a pattern that
  never appears here, so it never actually ran on real output. Now also
  checks that no *removed* attribute is referenced by the installed
  policy's constraints (via `seinfo --constrain`), and that Modified == 0.

Called as: store_sync_classify.py <installed_policy.35> <dryrun_policy.35>
       or: store_sync_classify.py --selftest
Prints PASS or FAIL, then reason: lines, then the raw sediff output.
Exit code is always 0 unless sediff itself fails (see gate_check.py's same
convention) -- the caller reads stdout.
"""
import os
import re
import subprocess
import sys

HEADER_RE = re.compile(
    r"^([A-Za-z_][A-Za-z_ ]*?)\s*\((\d+)\s*Added,\s*(\d+)\s*Removed(?:,\s*(\d+)\s*Modified)?\)\s*$"
)
MODIFIED_ONLY_HEADER_RE = re.compile(r"^([A-Za-z_][A-Za-z_ ]*?)\s*\((\d+)\s*Modified\)\s*$")

# Sections that must be EXACTLY zero -- any of these firing means the sync
# would change something beyond representation. Types and Type Attributes
# and Type_transition Rules are handled specially below, not here.
MUST_BE_ZERO = {
    "Policy Capabilities", "Constraints", "Validatetrans", "Portcons",
    "Netifcons", "Nodecons", "Genfscons", "Fs_uses", "Initial SIDs",
    "Default_users", "Default_roles", "Default_types", "Default_ranges",
    "Allow Rules", "Dontaudit Rules", "Auditallow Rules", "Neverallow Rules",
    "Booleans", "Role Allows", "Role Transitions", "Range Transitions",
    "Type Changes", "Type Members", "Bounds", "Allowxperm Rules",
    "Dontauditxperm Rules", "Auditallowxperm Rules", "Neverallowxperm Rules",
    "Permissive Types",
}

# Exactly one expected type_transition addition -- a checkpolicy expansion
# bug in the monolithic build (kubernetes.te:616 vs :254), CIL is right.
EXPECTED_TYPE_TRANSITION = "type_transition kubelet_t tmp_t:file kubernetes_tmp_t;"

TYPEATTR_RE = re.compile(r"^\S*_typeattr_\d+$")

# K1: sub-header count lines inside a body, not content to evaluate.
SUBHEADER_COUNT_RE = re.compile(r"^(Added|Removed|Modified) [A-Za-z_ ]+:\s*\d+$")
TYPE_BLOCK_RE = re.compile(r"^\*\s*(\S+)\s*\(([^)]*)\)\s*$")
ATTR_LINE_RE = re.compile(r"^[+-]\s*[A-Za-z_][A-Za-z0-9_]*$")


def run_sediff(a, b):
    proc = subprocess.run(["sediff", a, b], capture_output=True, text=True)
    if proc.returncode not in (0, 1):
        print(proc.stdout, file=sys.stdout)
        print(proc.stderr, file=sys.stderr)
        sys.exit(1)
    return proc.stdout


def find_headers(text):
    out = []
    for line in text.splitlines():
        m = HEADER_RE.match(line)
        if m:
            out.append((m.group(1).strip(), int(m.group(2)), int(m.group(3)),
                        int(m.group(4)) if m.group(4) is not None else 0))
            continue
        m = MODIFIED_ONLY_HEADER_RE.match(line)
        if m:
            out.append((m.group(1).strip(), 0, 0, int(m.group(2))))
    return out


def section_body(full_text, section_name):
    lines = full_text.splitlines()
    header_idx = [i for i, l in enumerate(lines)
                  if HEADER_RE.match(l) or MODIFIED_ONLY_HEADER_RE.match(l)]
    last_start = None
    for i in header_idx:
        m = HEADER_RE.match(lines[i]) or MODIFIED_ONLY_HEADER_RE.match(lines[i])
        if m.group(1).strip() == section_name:
            last_start = i
    if last_start is None:
        return ""
    end = len(lines)
    for i in header_idx:
        if i > last_start:
            end = i
            break
    return "\n".join(lines[last_start + 1:end])


def check_types_section(full_text, added, removed, reasons):
    # K3: a real added/removed TYPE (not just an attribute-set change) is
    # never acceptable here -- the header counts alone settle that.
    if added or removed:
        reasons.append(f"Types: Added/Removed count is ({added}, {removed}), expected (0, 0) -- "
                        "a type itself appeared or disappeared, not just an attribute change")

    body = section_body(full_text, "Types")
    in_attributes = False
    current_type = None
    for line in body.splitlines():
        s = line.strip()
        if not s or SUBHEADER_COUNT_RE.match(s):  # K1
            continue
        m = TYPE_BLOCK_RE.match(s)
        if m:
            current_type, detail = m.group(1), m.group(2)
            in_attributes = False
            # K3: only "N Added attributes"/"N Removed attributes" (comma-
            # joined) is expected in the parenthetical; anything mentioning
            # permissive status or aliases is a real behavioral change.
            if not re.match(r"^(\d+ Added attributes)?,?\s*(\d+ Removed attributes)?$", detail):
                reasons.append(f"Types: {current_type} changed in an unexpected way: ({detail})")
            continue
        if s == "Attributes:":
            in_attributes = True
            continue
        if s in ("Aliases:",) or s.startswith("Alias"):
            reasons.append(f"Types: {current_type or '?'} has an alias change, not expected here: {s}")
            continue
        if in_attributes and ATTR_LINE_RE.match(s):
            continue
        reasons.append(f"Types: unexpected line under {current_type or '?'}: {s!r}")


def check_type_attributes_section(full_text, modified, installed_policy, reasons):
    if modified:
        reasons.append(f"Type Attributes: Modified count is {modified}, expected 0")

    body = section_body(full_text, "Type Attributes")
    added, removed = [], []
    mode = None
    for line in body.splitlines():
        s = line.strip()
        if not s:
            continue
        if re.match(r"^Added Type Attributes:\s*\d+$", s):
            mode = "added"
            continue
        if re.match(r"^Removed Type Attributes:\s*\d+$", s):
            mode = "removed"
            continue
        m = re.match(r"^([+-])\s*(\S+)$", s)
        if not m:
            reasons.append(f"Type Attributes: unexpected line: {s!r}")
            continue
        name = m.group(2)
        if mode == "added":
            added.append(name)
        elif mode == "removed":
            removed.append(name)
        else:
            reasons.append(f"Type Attributes: attribute line outside Added/Removed block: {s!r}")

    # K4: added attributes must be CIL's auto-generated *_typeattr_N form.
    bad_added = [a for a in added if not TYPEATTR_RE.match(a)]
    if bad_added:
        reasons.append(f"Type Attributes: added attribute(s) not matching *_typeattr_N: {bad_added}")

    # K4: a removed attribute is only safe if nothing in the INSTALLED
    # policy's constraints actually references it.
    if removed and installed_policy:
        try:
            constrain_out = subprocess.run(
                ["seinfo", "--constrain", installed_policy],
                capture_output=True, text=True, timeout=30,
            ).stdout
        except Exception as e:
            reasons.append(f"Type Attributes: could not run seinfo --constrain to check removed "
                            f"attributes ({e}) -- treating as unverified, not safe to assume clean")
            constrain_out = None
        if constrain_out is not None:
            referenced = [a for a in removed if re.search(r"\b" + re.escape(a) + r"\b", constrain_out)]
            if referenced:
                reasons.append(f"Type Attributes: removed attribute(s) still referenced by a "
                                f"constraint in the installed policy: {referenced}")


def check_type_transition_section(full_text, added, removed, modified, reasons):
    if (added, removed, modified) != (1, 0, 0):
        reasons.append(f"Type_transition Rules: expected exactly (1 Added, 0 Removed, 0 Modified), "
                        f"got ({added}, {removed}, {modified})")

    body = section_body(full_text, "Type_transition Rules")
    added_lines, removed_lines = [], []
    for line in body.splitlines():
        s = line.strip()
        if s.startswith("+") and "type_transition" in s:
            added_lines.append(s.lstrip("+").strip())
        elif s.startswith("-") and "type_transition" in s:  # K5
            removed_lines.append(s.lstrip("-").strip())
    if removed_lines:
        reasons.append(f"Type_transition Rules: removed line(s) present, none expected: {removed_lines}")
    unexpected = [l for l in added_lines if l != EXPECTED_TYPE_TRANSITION]
    if unexpected:
        reasons.append(f"Type_transition Rules: unexpected added rule(s): {unexpected}")
    if EXPECTED_TYPE_TRANSITION not in added_lines:
        reasons.append(f"Type_transition Rules: expected rule not found: {EXPECTED_TYPE_TRANSITION!r} "
                        "(either fixed upstream now, or something else changed -- verify by hand)")


def classify(full_text, installed_policy=None):
    reasons = []
    seen = {}
    for name, added, removed, modified in find_headers(full_text):
        seen[name] = (added, removed, modified)

    for name, (added, removed, modified) in seen.items():
        total = added + removed + modified
        if total == 0:
            continue
        if name == "Types":
            check_types_section(full_text, added, removed, reasons)
        elif name == "Type Attributes":
            check_type_attributes_section(full_text, modified, installed_policy, reasons)
        elif name == "Type_transition Rules":
            check_type_transition_section(full_text, added, removed, modified, reasons)
        elif name in MUST_BE_ZERO:
            reasons.append(f"{name}: expected 0 differences, got ({added} Added, "
                            f"{removed} Removed, {modified} Modified)")
        else:
            reasons.append(f"unhandled/unexpected section: {name} ({added} Added, {removed} Removed"
                            f"{f', {modified} Modified' if modified else ''}) -- not in the known-residue list")

    return reasons


FIXTURE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "tests", "store_sync_dryrun_fixture.sediff")


def selftest():
    with open(FIXTURE_PATH) as f:
        good = f.read()

    failures = []

    reasons = classify(good, installed_policy=None)
    if reasons:
        failures.append(f"baseline fixture should PASS but got reasons: {reasons}")

    mutations = {
        "added type": good.replace(
            "Types (0 Added, 0 Removed, 1308 Modified)",
            "Types (1 Added, 0 Removed, 1308 Modified)"),
        "removed permissive": good.replace(
            "   Modified Types: 1308\n",
            "   Modified Types: 1308\n"
            "      * mutant_test_t (Removed permissive)\n"),
        "changed boolean default": good.replace(
            "Type_transition Rules (1 Added, 0 Removed, 0 Modified)",
            "Booleans (0 Added, 0 Removed, 1 Modified)\n"
            "   Modified Booleans: 1\n"
            "      * mutant_test_bool (changed)\n\n"
            "Type_transition Rules (1 Added, 0 Removed, 0 Modified)"),
        "extra type_transition": good.replace(
            "Type_transition Rules (1 Added, 0 Removed, 0 Modified)\n"
            "   Added Type_transition Rules: 1\n"
            "      + type_transition kubelet_t tmp_t:file kubernetes_tmp_t;",
            "Type_transition Rules (2 Added, 0 Removed, 0 Modified)\n"
            "   Added Type_transition Rules: 2\n"
            "      + type_transition kubelet_t tmp_t:file kubernetes_tmp_t;\n"
            "      + type_transition mutant_t foo_t:file bar_t;"),
    }
    for name, mutated in mutations.items():
        assert mutated != good, f"mutation {name!r} did not actually change the fixture text"
        reasons = classify(mutated, installed_policy=None)
        if not reasons:
            failures.append(f"mutation {name!r} should FAIL but classify() returned no reasons")

    if failures:
        print("SELFTEST FAIL")
        for f in failures:
            print(f"reason: {f}")
        sys.exit(1)
    print("SELFTEST PASS")


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        selftest()
        return
    if len(sys.argv) != 3:
        print("usage: store_sync_classify.py <installed_policy.35> <dryrun_policy.35>\n"
              "       store_sync_classify.py --selftest", file=sys.stderr)
        sys.exit(2)
    installed, dryrun = sys.argv[1], sys.argv[2]
    full_text = run_sediff(installed, dryrun)
    if not full_text.strip():
        print("FAIL")
        print("reason: sediff output is EMPTY -- the same file was almost certainly compared with itself")
        print()
        print(full_text)
        return
    reasons = classify(full_text, installed_policy=installed)
    if reasons:
        print("FAIL")
        for r in reasons:
            print(f"reason: {r}")
    else:
        print("PASS")
    print()
    print(full_text)


if __name__ == "__main__":
    main()
