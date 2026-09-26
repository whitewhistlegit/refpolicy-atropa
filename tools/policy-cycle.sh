#!/bin/bash
# policy-cycle.sh -- deterministic build/gate/install/load/verify/commit
# cycle for the atropa-refpolicy tree. Not security enforcement: it's a
# guard rail against mistakes, not a sandbox. `sudo sh -c '...'` or editing
# the store directly bypasses everything here.
#
# The additive/non-additive judgment is made entirely by tools/gate_check.py
# (a fail-closed allowlist over sediff's structured output), deliberately
# not left to whoever (human or LLM) is driving the cycle to eyeball --
# that's the whole point of this tool existing.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="$REPO/tools/.state"
POLICY_NAME="atropa-refpolicy"
INSTALLED_POLICY="/etc/selinux/${POLICY_NAME}/policy/policy.35"
INSTALLED_CONTEXTS_DIR="/etc/selinux/${POLICY_NAME}/contexts/files"
INSTALLED_FC="$INSTALLED_CONTEXTS_DIR/file_contexts"
INSTALLED_HOMEDIR="$INSTALLED_CONTEXTS_DIR/homedir_template"
RUNNING_POLICY="/sys/fs/selinux/policy"
BUILD_POLICY="$REPO/policy.35"
BUILD_FC="$REPO/file_contexts"
BUILD_HOMEDIR="$REPO/homedir_template"
BACKUP_DIR="$REPO/tools/.state/backups"

mkdir -p "$STATE_DIR" "$BACKUP_DIR"

GATE_STAMP="$STATE_DIR/gate-verdict"
BUILD_STAMP="$STATE_DIR/build-stamp"
VERIFY_STAMP="$STATE_DIR/verify-stamp"

die() {
	printf 'policy-cycle: ERROR: %s\n' "$*" >&2
	exit 1
}
info() { echo "policy-cycle: $*"; }

sha256_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

cmd_build() {
	cd "$REPO"

	# Refuse a build on master if any permissive line exists in the tree
	# (tracked OR untracked -- brave.te was untracked when this bit us
	# earlier tonight) -- this is the exact mistake that could have
	# silently shipped a fully-permissive domain in an unrelated build.
	local branch
	branch="$(git rev-parse --abbrev-ref HEAD)"
	if [ "$branch" = "master" ]; then
		if git grep --untracked -qE '^\s*permissive\s' -- 'policy/**/*.te' 2>/dev/null; then
			die "master has a 'permissive' line in policy/**/*.te (tracked or untracked) -- move it to its own branch first (git grep -n --untracked '^permissive' -- policy/ to find it)"
		fi
	fi

	info "building on branch '$branch' (no sudo -- compiling needs no privilege)..."
	local start_epoch
	start_epoch="$(date +%s)"

	# MONOLITHIC=y on BOTH clean and build: build.conf defaults to
	# MONOLITHIC=n, so an unqualified `make clean` is the modular clean
	# and never removes ./file_contexts -- that left a stale copy from
	# hours earlier that always "matched" the installed one, silently
	# disabling the file_contexts half of the gate.
	make MONOLITHIC=y TYPE=standard SYSTEMD=y clean >/dev/null
	make MONOLITHIC=y TYPE=standard SYSTEMD=y policy.35 file_contexts

	[ -f "$BUILD_POLICY" ] || die "build did not produce $BUILD_POLICY"
	[ -f "$BUILD_FC" ] || die "build did not produce $BUILD_FC"
	local fc_mtime
	fc_mtime="$(stat -c %Y "$BUILD_FC")"
	if [ "$fc_mtime" -lt "$start_epoch" ]; then
		die "$BUILD_FC is older than this build's start time -- it was not actually rebuilt (stale file from an earlier build). Do not trust this build's gate result."
	fi

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
		echo "policy_sha256=$(sha256_of "$BUILD_POLICY")"
		echo "fc_sha256=$(sha256_of "$BUILD_FC")"
	} > "$BUILD_STAMP"

	info "build OK. head=$head dirty=$dirty"
	cat "$BUILD_STAMP"
}

cmd_gate() {
	[ -f "$BUILD_STAMP" ] || die "no build stamp -- run 'build' first"
	[ -f "$BUILD_POLICY" ] || die "no $BUILD_POLICY -- run 'build' first"

	# A crash partway through must not leave a stale ADDITIVE stamp behind
	# for 'load' to trust later.
	rm -f "$GATE_STAMP"

	local gate_out verdict
	gate_out="$(python3 "$REPO/tools/gate_check.py" "$RUNNING_POLICY" "$BUILD_POLICY")"
	verdict="$(head -1 <<< "$gate_out")"

	local reasons=()
	if [ "$verdict" != "ADDITIVE" ]; then
		while IFS= read -r line; do
			[[ "$line" == reason:* ]] && reasons+=("${line#reason: }")
		done <<< "$gate_out"
		# Defense in depth: if gate_check.py said NON-ADDITIVE but (due to
		# a parsing gap here, not there) no reason: lines were extracted,
		# don't silently fall through to ADDITIVE below -- fail closed on
		# the verdict word itself.
		if [ "${#reasons[@]}" -eq 0 ]; then
			reasons+=("gate_check.py verdict: $verdict (no reason: lines parsed -- policy-cycle.sh parsing gap, not gate_check.py's)")
		fi
	fi

	# file_contexts and homedir_template: ANY difference is non-additive.
	# These relabel real files on disk and always need a deliberate
	# restorecon pass, never a live policy load.
	local fc_diff="" home_diff=""
	if [ -f "$BUILD_FC" ]; then
		if [ -f "$INSTALLED_FC" ]; then
			fc_diff="$(diff -u "$INSTALLED_FC" "$BUILD_FC" || true)"
		else
			fc_diff="(no installed file_contexts to diff against -- treating as changed)"
		fi
	fi
	if [ -f "$BUILD_HOMEDIR" ]; then
		if [ -f "$INSTALLED_HOMEDIR" ]; then
			home_diff="$(diff -u "$INSTALLED_HOMEDIR" "$BUILD_HOMEDIR" || true)"
		else
			home_diff="(no installed homedir_template to diff against -- treating as changed)"
		fi
	fi
	[ -n "$fc_diff" ] && reasons+=("file_contexts differs from installed")
	[ -n "$home_diff" ] && reasons+=("homedir_template differs from installed (HOME_DIR fc lines land here, not in file_contexts)")

	local build_sha running_sha
	build_sha="$(sha256_of "$BUILD_POLICY")"
	running_sha="$(sha256_of "$RUNNING_POLICY")"
	local final_verdict="ADDITIVE"
	[ "${#reasons[@]}" -gt 0 ] && final_verdict="NON-ADDITIVE"

	{
		echo "verdict=$final_verdict"
		echo "policy_sha256=$build_sha"
		echo "running_sha256=$running_sha"
		echo "checked_at=$(date -Iseconds)"
		echo "head=$(git -C "$REPO" rev-parse HEAD)"
		for r in "${reasons[@]}"; do echo "reason=$r"; done
	} > "$GATE_STAMP"

	echo "$gate_out"
	if [ -n "$fc_diff" ]; then
		echo "--- file_contexts diff (installed vs build) ---"
		echo "$fc_diff"
	fi
	if [ -n "$home_diff" ]; then
		echo "--- homedir_template diff (installed vs build) ---"
		echo "$home_diff"
	fi
	echo
	if [ "$final_verdict" = "ADDITIVE" ]; then
		info "VERDICT: ADDITIVE -- safe to install and (if sha matches after install) load live"
	else
		info "VERDICT: NON-ADDITIVE -- do not load live. Reasons:"
		for r in "${reasons[@]}"; do echo "  - $r"; done
		info "Install the file anyway if you want it to land at next boot, or setenforce 0 first if a live load is genuinely needed."
	fi
}

cmd_install() {
	[ -f "$BUILD_POLICY" ] || die "no $BUILD_POLICY -- run 'build' first"
	[ -f "$BUILD_STAMP" ] || die "no build stamp -- run 'build' first"
	[ -f "$GATE_STAMP" ] || die "no gate stamp -- run 'gate' first (installing an ungated build is exactly the mistake this tool exists to prevent)"
	cd "$REPO"

	local gate_sha build_fc_sha
	gate_sha="$(grep '^policy_sha256=' "$GATE_STAMP" | cut -d= -f2)"
	build_fc_sha="$(grep '^fc_sha256=' "$BUILD_STAMP" | cut -d= -f2)"
	[ "$gate_sha" = "$(sha256_of "$BUILD_POLICY")" ] || die "gate stamp's policy_sha256 does not match the current $BUILD_POLICY -- run 'gate' again before installing"

	local ts
	ts="$(date +%Y%m%d-%H%M%S)"
	local policy_backup="" contexts_backup=""
	if [ -f "$INSTALLED_POLICY" ]; then
		policy_backup="$BACKUP_DIR/policy.35.$ts"
		sudo cp "$INSTALLED_POLICY" "$policy_backup"
		info "backed up $INSTALLED_POLICY to $policy_backup"
	fi
	if [ -d "$INSTALLED_CONTEXTS_DIR" ]; then
		# Back up the WHOLE contexts/files dir, not just file_contexts and
		# homedir_template -- `make install` also regenerates
		# file_contexts.homedirs and the compiled .bin forms of both, none
		# of which a narrower per-file restore would roll back (Opus's
		# round-3 re-review finding).
		contexts_backup="$BACKUP_DIR/contexts-files.$ts"
		sudo cp -a "$INSTALLED_CONTEXTS_DIR" "$contexts_backup"
		info "backed up $INSTALLED_CONTEXTS_DIR to $contexts_backup"
	fi

	restore_backups() {
		if [ -n "$policy_backup" ]; then
			sudo cp "$policy_backup" "$INSTALLED_POLICY"
			info "restored $INSTALLED_POLICY from $policy_backup"
		fi
		if [ -n "$contexts_backup" ]; then
			sudo cp -a "$contexts_backup/." "$INSTALLED_CONTEXTS_DIR/"
			info "restored $INSTALLED_CONTEXTS_DIR from $contexts_backup"
		fi
	}

	# `make install` (not a manual cp) -- this is what actually installs
	# file_contexts and homedir_template too, runs setfiles -c validation,
	# genhomedircon and sefcontext_compile. A plain `cp policy.35` alone
	# left fc/homedir changes uninstalled forever.
	sudo make MONOLITHIC=y TYPE=standard SYSTEMD=y install

	cmp "$BUILD_POLICY" "$INSTALLED_POLICY" || { restore_backups; die "cmp mismatch after install -- installed policy.35 does not match build"; }
	if [ -f "$BUILD_FC" ] && [ -f "$INSTALLED_FC" ]; then
		cmp "$BUILD_FC" "$INSTALLED_FC" || { restore_backups; die "cmp mismatch after install -- installed file_contexts does not match build"; }
	fi

	# `make install` reruns the compile if anything in the tree is newer
	# than the last build artifact (e.g. a `make enableaudit`, which strips
	# every dontaudit rule, or a late .te edit after 'gate' ran) -- cmp
	# above would still pass because both copies are that SAME silent
	# rebuild, not the gated one. Pin the install to the exact bytes 'gate'
	# actually classified.
	local installed_sha installed_fc_sha
	installed_sha="$(sha256_of "$INSTALLED_POLICY")"
	if [ "$installed_sha" != "$gate_sha" ]; then
		restore_backups
		die "installed policy.35 sha256 ($installed_sha) does not match the gated sha256 ($gate_sha) -- 'make install' silently rebuilt from newer sources. Backups restored. Run 'build' and 'gate' again on the current tree, then 'install' again."
	fi
	if [ -f "$INSTALLED_FC" ] && [ -n "$build_fc_sha" ]; then
		installed_fc_sha="$(sha256_of "$INSTALLED_FC")"
		if [ "$installed_fc_sha" != "$build_fc_sha" ]; then
			restore_backups
			die "installed file_contexts sha256 does not match the gated build's fc_sha256 -- 'make install' silently rebuilt from newer sources. Backups restored. Run 'build' and 'gate' again, then 'install' again."
		fi
	fi

	info "installed OK, cmp + sha256 verified against the gated build (policy.35 + file_contexts). NOT loaded -- run 'load' explicitly if appropriate."
}

cmd_load() {
	[ -f "$GATE_STAMP" ] || die "no gate stamp -- run 'gate' first"
	[ -f "$INSTALLED_POLICY" ] || die "nothing installed -- run 'install' first"

	local verdict gate_sha gate_running_sha installed_sha current_running_sha enforce
	verdict="$(grep '^verdict=' "$GATE_STAMP" | cut -d= -f2)"
	gate_sha="$(grep '^policy_sha256=' "$GATE_STAMP" | cut -d= -f2)"
	gate_running_sha="$(grep '^running_sha256=' "$GATE_STAMP" | cut -d= -f2)"
	installed_sha="$(sha256_of "$INSTALLED_POLICY")"
	current_running_sha="$(sha256_of "$RUNNING_POLICY")"
	enforce="$(getenforce)"

	local gate_current=0
	if [ "$verdict" = "ADDITIVE" ] && [ "$gate_sha" = "$installed_sha" ] && [ "$gate_running_sha" = "$current_running_sha" ]; then
		gate_current=1
	fi

	if [ "$gate_current" -eq 1 ]; then
		info "gate says ADDITIVE, matches installed sha, and running policy hasn't moved since -- loading live"
	elif [ "$enforce" = "Permissive" ]; then
		info "system is Permissive -- loading anyway (gate verdict: $verdict)"
	else
		info "installed for next boot (verdict=$verdict, enforce=$enforce, gate_current=$gate_current). Not loading."
		exit 0
	fi

	sudo load_policy
	local post_diff
	post_diff="$(sediff --stats "$RUNNING_POLICY" "$INSTALLED_POLICY" 2>&1)"
	if [ -n "$post_diff" ]; then
		die "post-load sediff is NOT empty, running policy does not match installed:
$post_diff"
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
		echo "head=$(git -C "$REPO" rev-parse HEAD)"
		echo "build_sha=$(sha256_of "$BUILD_POLICY")"
		echo "args=$*"
		echo "running_ok=$([ -n "$out1" ] && echo yes || echo no)"
		echo "installed_ok=$([ -n "$out2" ] && echo yes || echo no)"
		echo "---"
	} >> "$VERIFY_STAMP"
}

cmd_verify_bool() {
	[ $# -eq 1 ] || die "usage: verify-bool <boolean_name>"
	local b="$1"
	echo "--- compiled default (installed policy.35) ---"
	seinfo -b "$b" -x "$INSTALLED_POLICY" 2>&1 || true
	echo "NOTE: '[ $b ]:True' on a rule means the rule lives in that boolean's TRUE branch, not that the boolean's value is true. Check the 'bool $b ...;' line for the actual default."
	echo
	echo "--- runtime value ---"
	getsebool "$b" 2>&1 || true
}

cmd_commit() {
	cd "$REPO"
	[ -f "$GATE_STAMP" ] || die "no gate stamp for current work -- run 'gate' before committing"
	[ -f "$VERIFY_STAMP" ] || die "no verify stamp -- run 'verify' at least once before committing"

	local branch
	branch="$(git rev-parse --abbrev-ref HEAD)"
	if [ "$branch" = "master" ] && git grep --untracked -qE '^\s*permissive\s' -- 'policy/**/*.te' 2>/dev/null; then
		die "refusing to commit: master has a 'permissive' line in policy/**/*.te"
	fi

	local head_now gate_head verify_last_head gate_sha verify_last_sha
	head_now="$(git rev-parse HEAD)"
	gate_head="$(grep '^head=' "$GATE_STAMP" | cut -d= -f2)"
	gate_sha="$(grep '^policy_sha256=' "$GATE_STAMP" | cut -d= -f2)"
	verify_last_head="$(grep '^head=' "$VERIFY_STAMP" | tail -1 | cut -d= -f2)"
	verify_last_sha="$(grep '^build_sha=' "$VERIFY_STAMP" | tail -1 | cut -d= -f2)"

	if [ "$gate_head" != "$head_now" ] || [ "$gate_sha" != "$(sha256_of "$BUILD_POLICY")" ]; then
		die "gate stamp is stale for the current head/build -- run 'build' and 'gate' again before committing"
	fi
	if [ "$verify_last_head" != "$head_now" ] || [ "$verify_last_sha" != "$(sha256_of "$BUILD_POLICY")" ]; then
		die "verify stamp is stale for the current head/build -- run 'verify' again before committing"
	fi

	local verdict
	verdict="$(grep '^verdict=' "$GATE_STAMP" | cut -d= -f2)"

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
