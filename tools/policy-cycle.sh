#!/bin/bash
# policy-cycle.sh -- deterministic build/gate/install/load/verify/commit
# cycle for the atropa-refpolicy tree. Not security enforcement: it's a
# guard rail against mistakes, not a sandbox. `sudo sh -c '...'` or editing
# the store directly bypasses everything here.
#
# The additive/non-additive judgment is made entirely by this script's
# `gate` subcommand from sediff output, deliberately not left to whoever
# (human or LLM) is driving the cycle -- that's the whole point of this
# tool existing.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="$REPO/tools/.state"
POLICY_NAME="atropa-refpolicy"
INSTALLED_POLICY="/etc/selinux/${POLICY_NAME}/policy/policy.35"
INSTALLED_FC="/etc/selinux/${POLICY_NAME}/contexts/files/file_contexts"
RUNNING_POLICY="/sys/fs/selinux/policy"
BUILD_POLICY="$REPO/policy.35"
BUILD_FC="$REPO/file_contexts"
BACKUP_DIR="$REPO/tools/.state/backups"

mkdir -p "$STATE_DIR" "$BACKUP_DIR"

GATE_STAMP="$STATE_DIR/gate-verdict"
BUILD_STAMP="$STATE_DIR/build-stamp"
VERIFY_STAMP="$STATE_DIR/verify-stamp"

die() { echo "policy-cycle: ERROR: $*" >&2; exit 1; }
info() { echo "policy-cycle: $*"; }

cmd_build() {
	cd "$REPO"

	# Refuse a build on master if any permissive line exists in the tree --
	# this is the exact mistake from earlier tonight (a diagnostic
	# `permissive brave_t;` left on master, which sediff would have shown
	# as purely additive and let straight through the gate).
	local branch
	branch="$(git rev-parse --abbrev-ref HEAD)"
	if [ "$branch" = "master" ]; then
		if git grep -qE '^\s*permissive\s' -- 'policy/**/*.te' 2>/dev/null; then
			die "master has a 'permissive' line in policy/**/*.te -- move it to its own branch first (git grep -n '^permissive' -- policy/ to find it)"
		fi
	fi

	info "building on branch '$branch'..."
	sudo make clean >/dev/null
	sudo make MONOLITHIC=y TYPE=standard SYSTEMD=y policy.35

	[ -f "$BUILD_POLICY" ] || die "build did not produce $BUILD_POLICY"

	local head dirty
	head="$(git rev-parse HEAD)"
	dirty="clean"
	git diff --quiet || dirty="dirty"
	git diff --cached --quiet || dirty="dirty"

	{
		echo "head=$head"
		echo "dirty=$dirty"
		echo "branch=$branch"
		echo "built_at=$(date -Iseconds)"
		echo "policy_sha256=$(sha256sum "$BUILD_POLICY" | cut -d' ' -f1)"
	} > "$BUILD_STAMP"

	info "build OK. head=$head dirty=$dirty"
	cat "$BUILD_STAMP"
}

cmd_gate() {
	[ -f "$BUILD_STAMP" ] || die "no build stamp -- run 'build' first"
	[ -f "$BUILD_POLICY" ] || die "no $BUILD_POLICY -- run 'build' first"

	local diff_out
	diff_out="$(sediff "$RUNNING_POLICY" "$BUILD_POLICY" 2>&1)" || die "sediff failed:\n$diff_out"

	local reasons=()
	local additive=1

	# Any "Removed ..." section with count > 0.
	while IFS= read -r line; do
		if [[ "$line" =~ \(([0-9]+)\ Added,\ ([0-9]+)\ Removed ]]; then
			local removed="${BASH_REMATCH[2]}"
			if [ "$removed" -gt 0 ]; then
				additive=0
				reasons+=("non-zero Removed count: $line")
			fi
		fi
	done <<< "$diff_out"

	# Modified rules: a bare "-perm" token anywhere inside a { ... } permission
	# set means something was taken away, not just added. sediff marks
	# additions with a leading '+' on the permission and removals with a
	# leading '-'; we only ever want to see '+'.
	if echo "$diff_out" | grep -qE '\{[^}]*[[:space:]]-[A-Za-z_]'; then
		additive=0
		reasons+=("a Modified rule has a -perm token (something removed, not just added)")
	fi

	# Any Modified Boolean at all is a default-state change -- the kernel
	# preserves runtime boolean values across a reload, so this can only be
	# safely applied by installing for next boot or via setenforce 0 first,
	# never loaded live even though it "looks" additive in isolation.
	if echo "$diff_out" | grep -qE '^[[:space:]]*Modified Booleans:[[:space:]]*[1-9]'; then
		additive=0
		reasons+=("a boolean default changed (Modified Booleans > 0) -- runtime value is preserved across reload, this needs next-boot or setenforce 0 first")
	fi

	# Any added or removed type_transition / role_transition / range_transition
	# is a labeling-behavior change, not a permission grant -- treat as
	# non-additive regardless of direction.
	if echo "$diff_out" | grep -qE '^[[:space:]]*(Type|Role|Range)_?[Tt]ransitions? .*\(([1-9][0-9]* Added|[1-9][0-9]* Removed)'; then
		additive=0
		reasons+=("a type_transition/role_transition/range_transition was added or removed")
	fi

	# Any removed permissive type.
	if echo "$diff_out" | grep -qE '^[[:space:]]*Permissive [Tt]ypes.*\([0-9]+ Added, [1-9][0-9]* Removed'; then
		additive=0
		reasons+=("a permissive type was removed")
	fi

	# A modified type that lost an attribute (sediff reports this under
	# "Modified Types" with a '-' attribute).
	if echo "$diff_out" | grep -qE '^[[:space:]]*\*.*attribute.*[[:space:]]-[A-Za-z_]'; then
		additive=0
		reasons+=("a type lost an attribute membership")
	fi

	# file_contexts: diff the installed fc against what this build would
	# install. ANY change here is non-additive for this gate -- fc changes
	# relabel real files on disk and need a deliberate restorecon pass, not
	# a live load.
	local fc_diff=""
	if [ -f "$INSTALLED_FC" ] && [ -f "$BUILD_FC" ]; then
		fc_diff="$(diff -u "$INSTALLED_FC" "$BUILD_FC" || true)"
	elif [ -f "$BUILD_FC" ]; then
		fc_diff="(no installed file_contexts to diff against -- treating as changed)"
	fi
	if [ -n "$fc_diff" ]; then
		additive=0
		reasons+=("file_contexts differs from installed -- affected paths need restorecon, not a live policy load:")
	fi

	local build_sha
	build_sha="$(sha256sum "$BUILD_POLICY" | cut -d' ' -f1)"

	{
		echo "verdict=$([ "$additive" -eq 1 ] && echo ADDITIVE || echo NON-ADDITIVE)"
		echo "policy_sha256=$build_sha"
		echo "checked_at=$(date -Iseconds)"
		for r in "${reasons[@]}"; do echo "reason=$r"; done
	} > "$GATE_STAMP"

	echo "$diff_out"
	echo
	if [ -n "$fc_diff" ]; then
		echo "--- file_contexts diff (installed vs build) ---"
		echo "$fc_diff"
		echo
	fi

	if [ "$additive" -eq 1 ]; then
		info "VERDICT: ADDITIVE -- safe to install and (if sha matches after install) load live"
	else
		info "VERDICT: NON-ADDITIVE -- do not load live. Reasons:"
		for r in "${reasons[@]}"; do echo "  - $r"; done
		info "Install the file anyway if you want it to land at next boot, or setenforce 0 first if a live load is genuinely needed."
	fi
}

cmd_install() {
	[ -f "$BUILD_POLICY" ] || die "no $BUILD_POLICY -- run 'build' first"

	local ts
	ts="$(date +%Y%m%d-%H%M%S)"
	if [ -f "$INSTALLED_POLICY" ]; then
		sudo cp "$INSTALLED_POLICY" "$BACKUP_DIR/policy.35.$ts"
		info "backed up installed policy.35 to $BACKUP_DIR/policy.35.$ts"
	fi
	if [ -f "$INSTALLED_FC" ]; then
		sudo cp "$INSTALLED_FC" "$BACKUP_DIR/file_contexts.$ts"
		info "backed up installed file_contexts to $BACKUP_DIR/file_contexts.$ts"
	fi

	sudo cp "$BUILD_POLICY" "$INSTALLED_POLICY"
	cmp "$BUILD_POLICY" "$INSTALLED_POLICY" || die "cmp mismatch after install -- installed file does not match build"
	info "installed OK, cmp verified. NOT loaded -- run 'load' explicitly if appropriate."
}

cmd_load() {
	[ -f "$GATE_STAMP" ] || die "no gate stamp -- run 'gate' first"
	[ -f "$INSTALLED_POLICY" ] || die "nothing installed -- run 'install' first"

	local verdict gate_sha installed_sha enforce
	verdict="$(grep '^verdict=' "$GATE_STAMP" | cut -d= -f2)"
	gate_sha="$(grep '^policy_sha256=' "$GATE_STAMP" | cut -d= -f2)"
	installed_sha="$(sha256sum "$INSTALLED_POLICY" | cut -d' ' -f1)"
	enforce="$(getenforce)"

	if [ "$verdict" = "ADDITIVE" ] && [ "$gate_sha" = "$installed_sha" ]; then
		info "gate says ADDITIVE and matches installed sha -- loading live"
	elif [ "$enforce" = "Permissive" ]; then
		info "system is Permissive -- loading anyway (gate verdict: $verdict)"
	else
		info "installed for next boot (verdict=$verdict, enforce=$enforce, gate_sha_matches_installed=$([ "$gate_sha" = "$installed_sha" ] && echo yes || echo no)). Not loading."
		exit 0
	fi

	sudo load_policy
	local post_diff
	post_diff="$(sediff --stats "$RUNNING_POLICY" "$INSTALLED_POLICY" 2>&1)"
	if echo "$post_diff" | grep -qE '\([1-9]'; then
		die "post-load sediff is NOT all-zero, running policy does not match installed:\n$post_diff"
	fi
	info "load OK, post-load sediff confirms running == installed"
}

cmd_verify() {
	[ $# -ge 1 ] || die "usage: verify <sesearch args...>"
	echo "--- against running policy ($RUNNING_POLICY) ---"
	local out1
	out1="$(sesearch "$@" "$RUNNING_POLICY" 2>&1)" || true
	echo "$out1"
	[ -n "$out1" ] && echo "OK (found)" || echo "MISS (not found)"
	echo
	echo "--- against installed policy ($INSTALLED_POLICY) ---"
	local out2
	out2="$(sesearch "$@" "$INSTALLED_POLICY" 2>&1)" || true
	echo "$out2"
	[ -n "$out2" ] && echo "OK (found)" || echo "MISS (not found)"

	{
		echo "verified_at=$(date -Iseconds)"
		echo "args=$*"
		echo "running_ok=$([ -n "$out1" ] && echo yes || echo no)"
		echo "installed_ok=$([ -n "$out2" ] && echo yes || echo no)"
	} >> "$VERIFY_STAMP"
}

cmd_verify_bool() {
	[ $# -eq 1 ] || die "usage: verify-bool <boolean_name>"
	local b="$1"
	echo "--- compiled default (installed policy.35) ---"
	seinfo -b "$b" -x "$INSTALLED_POLICY" 2>&1 || true
	echo "NOTE: '[ $b ]:True' on a rule means the rule lives in that boolean's TRUE branch, not that the boolean's value is true. Check the line above this one for the actual bool default."
	echo
	echo "--- runtime value ---"
	getsebool "$b" 2>&1 || true
}

cmd_commit() {
	[ -f "$GATE_STAMP" ] || die "no gate stamp for current work -- run 'gate' before committing"
	[ -f "$VERIFY_STAMP" ] || die "no verify stamp -- run 'verify' at least once before committing"

	cd "$REPO"
	local branch
	branch="$(git rev-parse --abbrev-ref HEAD)"
	if [ "$branch" = "master" ] && git grep -qE '^\s*permissive\s' -- 'policy/**/*.te' 2>/dev/null; then
		die "refusing to commit: master has a 'permissive' line in policy/**/*.te"
	fi

	local verdict gate_sha head_now gate_stamp_age
	verdict="$(grep '^verdict=' "$GATE_STAMP" | cut -d= -f2)"
	head_now="$(git rev-parse HEAD)"

	echo "--- suggested commit message body (edit before using) ---"
	echo "sediff gate verdict: $verdict"
	sediff --stats "$RUNNING_POLICY" "$BUILD_POLICY" 2>&1 || true
	echo
	echo "Observed, not inferred: state exactly what ausearch/sesearch/journalctl showed."
	echo "Do not describe a rule's purpose as fact unless you saw the denial it fixes."
	echo
	echo "git commit -m \"<summary>\" -m \"<body>\" -m \"Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>\""
}

case "${1:-}" in
	build) shift; cmd_build "$@" ;;
	gate) shift; cmd_gate "$@" ;;
	install) shift; cmd_install "$@" ;;
	load) shift; cmd_load "$@" ;;
	verify) shift; cmd_verify "$@" ;;
	verify-bool) shift; cmd_verify_bool "$@" ;;
	commit) shift; cmd_commit "$@" ;;
	*)
		echo "usage: policy-cycle.sh {build|gate|install|load|verify <sesearch-args>|verify-bool <name>|commit}"
		exit 1
		;;
esac
