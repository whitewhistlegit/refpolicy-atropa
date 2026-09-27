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
set -Eeuo pipefail
# A `set -e` exit is otherwise silent about WHERE it happened -- Opus's
# dryrun #2 caught a case (an empty grep inside a command substitution,
# under pipefail) that killed a store-sync-dryrun check with no message at
# all. Every unexpected exit from here on prints the failing line number.
# -E: without it, this trap only fires for a failure at the top level, not
# one inside a function -- and nearly everything this script does runs
# inside a function. Without -E the failure would still be fatal (`set -e`
# still exits), just silently, with no line number printed (Opus's
# adversarial pass on store-sync-finalize, 2026-09-27).
trap 'echo "policy-cycle: unexpected exit (see the command at line $LINENO above)" >&2' ERR

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

STORE_DIR="/var/lib/selinux/${POLICY_NAME}"
STORE_ETC_DIR="/etc/selinux/${POLICY_NAME}"
STORE_USR_DIR="/usr/share/selinux/${POLICY_NAME}"
STORE_MARKER="$HOME/.config/atropa/store-synced"
STORE_BACKUP_DIR="$REPO/tools/.state/store-backups"
STORE_SCRATCH_DIR="$REPO/tools/.state/store-sync-scratch"
STORE_LOCK_FILE="$STATE_DIR/store-sync.lock"
MODULES_CONF="$REPO/policy/modules.conf"
# The 24 local audit2allow modules identified in Opus's 2026-09-26 store
# audit (~/claude-readme/opus-5-5/README.md §3e/3e-bis; sources at
# ~/.local/share/atropa/selinux-review/approved/) -- ad hoc fixes that
# predate tonight's proper .te-level fixes for the same denials, or were
# superseded by an explicit decision (e.g. VideoDevicePoll's io_uring
# allow, replaced by a deliberate dontaudit). All 24 are foreign to the
# tree (never in policy/modules.conf) and slated for removal in one
# `make pure-load` transaction: 4 had unique coverage, now folded into
# the tree (f16b104, independently verified); the rest are pure
# duplicates or deliberately-reversed hacks. Two of requiredmod's rules
# (an unconfirmed inherited socket, a var_run_t sock_file write) have no
# tree equivalent yet -- their removal is an accepted, permissive-mode
# risk to be verified at the next boot, not folded speculatively.
# This hardcoded list is a cross-check, not the source of truth: apply
# computes the actual foreign set live (semodule -l minus modules.conf's
# base/module entries) and refuses to proceed if it doesn't match this
# exactly, in case the store has drifted since the 2026-09-26 audit.
STORE_LEGACY_MODULES=(
	VideoDevicePoll backlighthelper bluetoothd dbus-broker dbus-broker-lau
	fsck gmain journalctl kdeconnectd ksplashqml modprobe net plasmashell
	polkit-agent-he polkit-kde-auth polkitd requiredmod sddm-helper
	sedispatch semodule setsebool startplasma-x11 systemctl udevuevent
)
# booleans.local's current 8 true booleans (preserve) + 2 known
# tonight-only additions the store doesn't have yet: user_execmod_tmpfs
# (fold-now decision) and brave_read_system_info (Brave GPU fix, 555378e
# -- only a .te compiled-default change so far, never pushed to the store).
STORE_INTENDED_TRUE_BOOLEANS=(
	xserver_allow_dri systemd_tmpfiles_manage_all aide_mmap_files
	clamav_read_user_content_files_clamscan
	clamav_read_all_non_security_files_clamscan
	dbus_broker_system_bus dbus_broker_run_transient_units allow_execmem
	user_execmod_tmpfs brave_read_system_info
)

store_tree_modules() {
	# "base" (the merged base .te's) plus every modules.conf "= module"
	# entry -- i.e. every module name our own tree would install, by
	# semodule's naming (module .te basename).
	{ echo base; grep -oE '^\S+ = module$' "$MODULES_CONF" | cut -d' ' -f1; } | sort -u
}

store_foreign_modules() {
	# Foreign = everything semodule -l lists that isn't in store_tree_modules.
	# Per Opus's B3, this is computed directly (not via `make pure-load`'s
	# internal $(shell semodule -l), which fails open to an empty removal
	# list if the shell call itself fails) so apply can assert it against
	# STORE_LEGACY_MODULES before ever running a real transaction.
	local installed
	installed="$(sudo semodule -l | sort -u)"
	comm -23 <(echo "$installed") <(store_tree_modules)
}

store_commit_num() {
	sudo cat "$STORE_DIR/active/commit_num" 2>/dev/null | tr -d '[:space:]'
}

store_etc_tree_sha() {
	# A single combined hash standing in for "the /etc side hasn't moved" --
	# used by the state-aware re-run check (R2), not as a security control.
	sudo find "$STORE_ETC_DIR" -type f -exec sha256sum {} + 2>/dev/null | sort | sha256sum | cut -d' ' -f1
}

store_backup_all() {
	# R1: all three trees libsemanage/checkpolicy touch, not just two.
	#
	# $1: "pre-sync" (called from within cmd_store_sync_apply, before any
	# change is made -- restoring this backup UNDOES the sync attempt, so
	# the runbook must delete the marker too) or "post-sync" (an ad-hoc
	# snapshot of an already-synced, already-verified state -- restoring
	# THIS backup reproduces that same synced state, so the marker must
	# NOT be touched, or a restore would wrongly reopen the retired
	# monolithic path and re-block semodule/semanage). Required: the
	# original runbook template hardcoded pre-sync wording even when this
	# function was used to snapshot an already-synced state (Opus,
	# 2026-09-27) -- the wrongness wasn't in the backup itself, it was in
	# describing a post-sync backup with pre-sync instructions.
	local context="$1"
	case "$context" in
		pre-sync|post-sync) ;;
		*) die "store_backup_all: \$1 must be 'pre-sync' or 'post-sync', got '${context:-<empty>}'" ;;
	esac

	local ts backup_dir runbook
	ts="$(date +%Y%m%d-%H%M%S)"
	backup_dir="$STORE_BACKUP_DIR/$ts"
	mkdir -p "$backup_dir"

	# Fixed 2026-09-27 (Opus's finding): tarballs used to be named
	# "$(basename "$src").tar.gz", but all three trees share the same
	# basename ("atropa-refpolicy") -- every backup in this loop silently
	# overwrote the previous one, and only the LAST tree's tarball ever
	# survived. The 2026-09-26 real-run backup was affected: its single
	# surviving tarball held only the /usr/share tree (429 .pp files),
	# with no active/ (no module store) and no policy.35 (no /etc tree) --
	# the RESTORE runbook it generated would have DESTROYED the store, not
	# restored it, had anyone followed it. Distinct labels per tree now,
	# never basename.
	local src_name label
	for src_name in STORE_DIR STORE_ETC_DIR STORE_USR_DIR; do
		case "$src_name" in
			STORE_DIR) label=store ;;
			STORE_ETC_DIR) label=etc ;;
			STORE_USR_DIR) label=usr ;;
		esac
		local src="${!src_name}" tarname base listing
		tarname="$backup_dir/$label.tar.gz"
		# A missing source tree used to be a WARNING+skip -- silently
		# proceeding with 2 of 3 trees backed up is worse than refusing
		# outright, since a later restore would have no idea a tree is
		# missing until it's needed (Opus, 2026-09-27).
		[ -d "$src" ] || die "$src does not exist -- refusing to take a partial backup. Investigate before retrying."
		# --selinux is a silent no-op on this system's tar (Arch's GNU tar
		# 1.35 has no libselinux support built in) -- security.selinux
		# labels were NOT being preserved despite the flag appearing to
		# ask for them. --xattrs alone also excludes the security.*
		# namespace by default (a safety default, not a bug) -- explicitly
		# include it. Opus round-tripped this in scratch and confirmed
		# labels survive create+extract with this combination.
		sudo tar --xattrs --xattrs-include='security.selinux' --acls -czf "$tarname" -C "$(dirname "$src")" "$(basename "$src")"
		sudo tar -tzf "$tarname" >/dev/null || die "backup tar for $src failed verification (tar -tzf)"

		# Positive content check: `tar -tzf` exiting 0 only proves the
		# archive is well-formed, NOT that it holds the right tree --
		# every one of the three collided tarballs above would have
		# passed that check too. Fail closed on the specific files each
		# tree must contain.
		#
		# Here-string, not `echo "$listing" | grep -qx ...`: the store
		# listing alone is ~83KB, bigger than a pipe's buffer -- an early
		# grep match can close its stdin while `echo` is still writing,
		# SIGPIPEing the echo (exit 141) and tripping `|| die` on a
		# perfectly good backup. Only ever passed before by luck of
		# listing order (Opus, 2026-09-27). <<< avoids the pipe entirely.
		base="$(basename "$src")"
		listing="$(sudo tar -tzf "$tarname")"
		case "$label" in
			store)
				grep -qx "$base/active/commit_num" <<<"$listing" \
					|| die "backup tar for $src ($tarname) is missing $base/active/commit_num -- refusing to trust this backup"
				grep -qx "$base/active/policy.kern" <<<"$listing" \
					|| die "backup tar for $src ($tarname) is missing $base/active/policy.kern -- refusing to trust this backup"
				;;
			etc)
				grep -qx "$base/policy/policy.35" <<<"$listing" \
					|| die "backup tar for $src ($tarname) is missing $base/policy/policy.35 -- refusing to trust this backup"
				grep -qx "$base/contexts/files/file_contexts" <<<"$listing" \
					|| die "backup tar for $src ($tarname) is missing $base/contexts/files/file_contexts -- refusing to trust this backup"
				;;
			usr)
				grep -qx "$base/base.pp" <<<"$listing" \
					|| die "backup tar for $src ($tarname) is missing $base/base.pp -- refusing to trust this backup"
				;;
		esac
		info "backed up $src -> $tarname ($(du -h "$tarname" | cut -f1)) -- content check OK"
	done

	# 2026-09-27 (Opus's finding): the runbook used to unconditionally
	# describe a PRE-sync backup (delete the marker, "restores exactly the
	# pre-sync state") even when this function was used to snapshot an
	# already-synced, already-verified state -- following those
	# instructions on a post-sync backup would have deleted a perfectly
	# correct marker and wrongly reopened the retired monolithic path.
	local header_line footer_note marker_block stage_dir base_store base_etc base_usr
	stage_dir="/tmp/atropa-restore-staging-$ts"
	base_store="$(basename "$STORE_DIR")"
	base_etc="$(basename "$STORE_ETC_DIR")"
	base_usr="$(basename "$STORE_USR_DIR")"
	if [ "$context" = "pre-sync" ]; then
		header_line="RESTORE runbook for the $ts store-sync-apply attempt (PRE-sync backup)"
		footer_note="This restores the PRE-sync state of all three trees, as they were
immediately before this store-sync-apply attempt began. It does NOT
restore booleans.local if 'semanage boolean -D' already ran as part of
that attempt -- re-set those 8 booleans by hand if needed (see the
sync's own output for the list, or ~/claude-readme/sonnet-5/MEMORY.md)."
		marker_block="# S6: absolute path, not ~ -- this runs from a root shell, where ~
# means /root, not \$HOME. Without this, the hook would still treat the
# restored (stale, pre-sync) store as synced and allow module ops
# against it.
sudo rm -f $STORE_MARKER"
	else
		local backup_commit
		backup_commit="$(store_commit_num)"
		header_line="RESTORE runbook for the $ts backup (POST-sync, verified-good state)"
		footer_note="This restores the VERIFIED-GOOD POST-sync state of all three trees
(store commit_num $backup_commit at backup time) -- NOT a pre-sync
state. Do NOT delete $STORE_MARKER after restoring it: the restored
state genuinely IS synced, and deleting the marker would wrongly
reopen the retired monolithic gate/install/load path and re-block
semodule/semanage for no reason."
		marker_block="# post-sync backup -- the marker is intentionally left untouched here;
# see the note at the end of this file."
	fi

	runbook="$backup_dir/RESTORE.txt"
	cat > "$runbook" <<-EOF
	$header_line
	=====================================================
	Run this from a root shell (a text console works -- no desktop/dbus
	required). Extracts into a staging dir and verifies key files are
	present BEFORE touching anything live; the current live trees are
	renamed aside (*.old.$ts) rather than deleted, so there's something
	to inspect/recover from if this goes wrong partway (fixed 2026-09-27
	after Opus flagged the old version as rm -rf'ing all three live
	trees before ever confirming the tarballs extract cleanly):

	set -e   # stop on the first failure -- the staging checks below only
	         # protect you if a failing 'test -f' actually halts the script
	cd $backup_dir
	sudo rm -rf $stage_dir
	sudo mkdir -p $stage_dir/var-lib-selinux $stage_dir/etc-selinux $stage_dir/usr-share-selinux
	sudo tar --xattrs --xattrs-include='security.selinux' --acls -xzf store.tar.gz -C $stage_dir/var-lib-selinux
	sudo tar --xattrs --xattrs-include='security.selinux' --acls -xzf etc.tar.gz -C $stage_dir/etc-selinux
	sudo tar --xattrs --xattrs-include='security.selinux' --acls -xzf usr.tar.gz -C $stage_dir/usr-share-selinux

	# verify key files landed in staging BEFORE touching anything live
	sudo test -f $stage_dir/var-lib-selinux/$base_store/active/commit_num
	sudo test -f $stage_dir/var-lib-selinux/$base_store/active/policy.kern
	sudo test -f $stage_dir/etc-selinux/$base_etc/policy/policy.35
	sudo test -f $stage_dir/etc-selinux/$base_etc/contexts/files/file_contexts
	sudo test -f $stage_dir/usr-share-selinux/$base_usr/base.pp

	setenforce 0   # if not already permissive

	sudo mv $STORE_DIR ${STORE_DIR}.old.$ts 2>/dev/null || true
	sudo mv $STORE_ETC_DIR ${STORE_ETC_DIR}.old.$ts 2>/dev/null || true
	sudo mv $STORE_USR_DIR ${STORE_USR_DIR}.old.$ts 2>/dev/null || true

	sudo mv $stage_dir/var-lib-selinux/$base_store $STORE_DIR
	sudo mv $stage_dir/etc-selinux/$base_etc $STORE_ETC_DIR
	sudo mv $stage_dir/usr-share-selinux/$base_usr $STORE_USR_DIR

	# belt-and-braces: --xattrs-include restores the security.selinux xattr
	# from the tarball, but re-labeling from the live policy is a cheap,
	# independent second check that costs nothing (Opus, 2026-09-27).
	sudo restorecon -RFv $STORE_DIR $STORE_ETC_DIR $STORE_USR_DIR

	$marker_block

	sudo load_policy
	sesearch -A -s aide_t $RUNNING_POLICY | head -1   # sanity: command runs, some output
	getenforce   # confirm still Permissive before trusting anything further

	store.tar.gz = $STORE_DIR, etc.tar.gz = $STORE_ETC_DIR, usr.tar.gz =
	$STORE_USR_DIR -- distinct names, not basename, so they can never
	collide the way the 2026-09-26 backup did (see
	tools/.state/store-backups/20260926-225855/README-WHY-BROKEN.txt).
	$footer_note
	EOF
	sudo cp "$runbook" "/root/store-sync-RESTORE-$ts.txt" 2>/dev/null \
		&& info "RESTORE runbook also copied to /root/store-sync-RESTORE-$ts.txt (readable from a text console)" \
		|| info "WARNING: could not copy RESTORE runbook to /root -- it's still at $runbook"
	info "RESTORE runbook: $runbook"
}

store_build_modular() {
	# B2: MONOLITHIC=n clean first, or the stale monolithic tmp/ poisons
	# base.conf (this already happened once: a 57MB base.pp instead of
	# the expected ~0.6MB). No sudo -- compiling needs none.
	cd "$REPO"
	make MONOLITHIC=n clean >/dev/null
	make MONOLITHIC=n all >/dev/null

	[ -f "$REPO/base.pp" ] || die "modular build did not produce base.pp"
	local base_size
	base_size="$(stat -c %s "$REPO/base.pp")"
	[ "$base_size" -lt 1048576 ] || die "base.pp is ${base_size} bytes (>1MB) -- looks like the monolithic-tmp-poisoning bug (B2). Refusing."
	grep -qa brave_xdg_cache_t "$REPO/base.pp" && die "base.pp contains brave_xdg_cache_t -- it should only be in brave's own module, another sign of B2 recurring."

	local m missing=()
	for m in $(store_tree_modules); do
		[ "$m" = base ] && continue
		[ -f "$REPO/$m.pp" ] || missing+=("$m")
	done
	[ "${#missing[@]}" -eq 0 ] || die "modular build did not produce: ${missing[*]}"

	# Manifest: re-checked immediately before the real run so nothing can
	# change between the dry run and the real one (B3's "pin the bytes").
	# sha256sum -c's own format ("<hex>  <relative-path>"), so
	# store_check_manifest can just run sha256sum -c from $REPO.
	{
		echo "$(sha256_of "$REPO/base.pp")  base.pp"
		for m in $(store_tree_modules); do
			[ "$m" = base ] && continue
			echo "$(sha256_of "$REPO/$m.pp")  $m.pp"
		done
	} | sort -k2 > "$STATE_DIR/store-sync-manifest.sha256"
	info "modular build OK: base.pp ($base_size bytes) + $(( $(store_tree_modules | wc -l) - 1 )) module packages"
}

store_check_manifest() {
	(cd "$REPO" && sha256sum -c "$STATE_DIR/store-sync-manifest.sha256" --quiet)
}

# Populates the global STORE_SEMODULE_ARGS array with the pinned argv
# (module installs + foreign removals), shared verbatim between the dry
# run and the real run per B3 -- no -X anywhere, so everything lands/stays
# at the store's existing priority 400.
#
# S3: built ONCE, right after cmd_store_sync_apply's step-4 assertion, from
# the ALREADY-asserted STORE_LEGACY_MODULES -- never from a fresh
# `store_foreign_modules` (live `semodule -l`) call at real-run time. `$(...)`
# doesn't inherit `set -e`, so a transient semodule -l failure there would
# silently produce an EMPTY -r list: the tree installs, nothing gets
# removed, no error -- the exact pure-load failure mode B3 exists to avoid.
# Also asserts the resulting argv has exactly 24 -r and 428 -i (1 base +
# 427 tree modules), and logs a sha256 of the argv so real-run can confirm
# nothing rebuilt it differently in between.
store_build_argv() {
	local tree_mods tree_count
	tree_mods="$(store_tree_modules)"
	tree_count="$(echo "$tree_mods" | wc -l)"

	STORE_SEMODULE_ARGS=(-s "$POLICY_NAME")
	local m
	STORE_SEMODULE_ARGS+=(-i "$REPO/base.pp")
	for m in $tree_mods; do
		[ "$m" = base ] && continue
		STORE_SEMODULE_ARGS+=(-i "$REPO/$m.pp")
	done
	for m in "${STORE_LEGACY_MODULES[@]}"; do
		STORE_SEMODULE_ARGS+=(-r "$m")
	done

	local i_count r_count
	i_count="$(printf '%s\n' "${STORE_SEMODULE_ARGS[@]}" | grep -c '^-i$')"
	r_count="$(printf '%s\n' "${STORE_SEMODULE_ARGS[@]}" | grep -c '^-r$')"
	[ "$i_count" -eq "$tree_count" ] || die "argv has $i_count -i flags, expected $tree_count (base + tree modules) -- refusing to build a mismatched commit."
	[ "$r_count" -eq "${#STORE_LEGACY_MODULES[@]}" ] || die "argv has $r_count -r flags, expected ${#STORE_LEGACY_MODULES[@]} -- refusing to build a mismatched commit."

	STORE_SEMODULE_ARGS_SHA="$(printf '%s\0' "${STORE_SEMODULE_ARGS[@]}" | sha256sum | cut -d' ' -f1)"
	info "argv built: $i_count -i, $r_count -r (sha256 $STORE_SEMODULE_ARGS_SHA)"
}

store_dry_run() {
	# S1: `sudo semodule` runs confined as semanage_t. Plain `mkdir` leaves
	# the scratch parents user_home_t, and semanage_t only has getattr/
	# open/search there -- it needs to CREATE subdirectories (e.g.
	# <root>/var/lib/selinux/final) while Enforcing, which user_home_t
	# denies. Use `sudo install -d` + chcon --reference against the real
	# locations instead of a plain mkdir, and never chown the copy to the
	# calling user (root needs to keep owning what it's about to write
	# into). The files inside are root-owned after any run, so cleanup
	# must be `sudo rm -rf` too, or a re-run dies under set -e.
	sudo rm -rf "$STORE_SCRATCH_DIR"
	local scratch_var_lib_selinux="$STORE_SCRATCH_DIR$(dirname "$STORE_DIR")"
	local scratch_etc_selinux="$STORE_SCRATCH_DIR$(dirname "$STORE_ETC_DIR")"
	sudo install -d -m 0755 "$scratch_var_lib_selinux" "$scratch_etc_selinux"
	sudo chcon --reference=/var/lib/selinux "$scratch_var_lib_selinux"
	sudo chcon --reference=/etc/selinux "$scratch_etc_selinux"
	sudo cp -a "$STORE_DIR" "$scratch_var_lib_selinux/"
	sudo cp -a "$STORE_ETC_DIR" "$scratch_etc_selinux/"

	info "dry run: semodule ${STORE_SEMODULE_ARGS[*]} -p $STORE_SCRATCH_DIR -N"
	sudo semodule "${STORE_SEMODULE_ARGS[@]}" -p "$STORE_SCRATCH_DIR" -N \
		|| die "dry run FAILED -- see semodule's output above. Nothing live was touched."
	info "dry run OK (scratch store at $STORE_SCRATCH_DIR, untouched by the real system)"
}

store_real_run() {
	store_check_manifest || die "manifest changed since the build/dry-run step -- something modified base.pp or a module .pp between then and now. Refusing to run for real. Re-run from 'build_modular'."

	# S3 defense-in-depth: the argv was built once (right after the step-4
	# assertion); re-verify here, right before firing, that (a) nothing
	# rebuilt STORE_SEMODULE_ARGS differently in the meantime (sha check)
	# and (b) the live foreign set hasn't drifted from what it was built
	# against -- the operator may have sat at the "yes" prompt for a while.
	local current_sha
	current_sha="$(printf '%s\0' "${STORE_SEMODULE_ARGS[@]}" | sha256sum | cut -d' ' -f1)"
	[ "$current_sha" = "$STORE_SEMODULE_ARGS_SHA" ] || die "argv sha changed since it was built ($STORE_SEMODULE_ARGS_SHA -> $current_sha) -- refusing to run an argv that mutated underneath us."
	local live_foreign_sorted expected_sorted
	live_foreign_sorted="$(store_foreign_modules | sort -u)"
	expected_sorted="$(printf '%s\n' "${STORE_LEGACY_MODULES[@]}" | sort -u)"
	[ "$live_foreign_sorted" = "$expected_sorted" ] || die "live foreign-module set drifted since the argv was built -- refusing the real run. Start over from 'store-sync-dryrun'."

	info "REAL run: semodule ${STORE_SEMODULE_ARGS[*]} -N"
	sudo semodule "${STORE_SEMODULE_ARGS[@]}" -N \
		|| die "REAL semodule commit FAILED or partially applied -- system may be in a 3-state (store old/new x /etc old/new) mixed state. DO NOT GUESS. Use the RESTORE runbook from step 2, then verify getenforce is still Permissive before doing anything else."

	local post_commit
	post_commit="$(store_commit_num)"
	info "store commit_num is now $post_commit"

	# -N above deliberately left the running kernel policy untouched as an
	# extra checkpoint -- the commit is on disk (INSTALLED_POLICY reflects
	# it) but not yet live. Load it now, explicitly, the same way cmd_load
	# does, and confirm running == installed before calling this done.
	# Safe regardless of gate state: we are Permissive at this point.
	sudo load_policy || die "load_policy FAILED after a successful semodule commit -- on-disk policy is the new synced one, but the kernel is still running the old one. Use the RESTORE runbook, or investigate before retrying load_policy alone (do not re-run the semodule commit)."
	local post_load_diff
	post_load_diff="$(sediff --stats "$RUNNING_POLICY" "$INSTALLED_POLICY" 2>&1)"
	[ -z "$post_load_diff" ] || die "post-load sediff is NOT empty -- running policy does not match installed after load_policy:
$post_load_diff"
	info "load_policy OK -- running policy now matches the synced installed policy"
}

store_verify_after_sync() {
	# $1 = pre-sync commit_num (S4: commit_num must be exactly pre+1).
	local pre_commit="$1"
	# V4 fix: stdout only, exit code checked, no stderr-counts-as-found.
	local ok=1
	local out
	if ! out="$(sesearch -A -s aide_t "$INSTALLED_POLICY" 2>/dev/null)"; then
		info "VERIFY FAIL: sesearch against installed policy errored"
		ok=0
	elif [ -z "$out" ]; then
		info "VERIFY FAIL: sesearch against installed policy returned nothing for aide_t (expected some rules)"
		ok=0
	fi

	# S4/V1: module set == store_tree_modules in BOTH directions -- not
	# just "no foreign left" (which alone would miss a tree module that
	# silently failed to install).
	local remaining missing_tree installed_sorted tree_sorted
	remaining="$(store_foreign_modules)"
	if [ -n "$remaining" ]; then
		info "VERIFY FAIL: foreign modules still present after sync: $remaining"
		ok=0
	fi
	installed_sorted="$(sudo semodule -l | sort -u)"
	tree_sorted="$(store_tree_modules | sort -u)"
	missing_tree="$(comm -23 <(echo "$tree_sorted") <(echo "$installed_sorted"))"
	if [ -n "$missing_tree" ]; then
		info "VERIFY FAIL: tree modules missing from the store after sync: $missing_tree"
		ok=0
	fi

	# S4/V1: commit_num must be exactly pre+1 -- anything else means either
	# nothing committed, or something else committed in between.
	local post_commit expected_commit
	post_commit="$(store_commit_num)"
	expected_commit=$((pre_commit + 1))
	if [ "$post_commit" != "$expected_commit" ]; then
		info "VERIFY FAIL: commit_num is $post_commit, expected exactly $expected_commit (pre-sync was $pre_commit)"
		ok=0
	fi

	# S4/V1: the real run's on-disk outputs must be byte-identical to what
	# the dry run already produced against the scratch copy -- if they
	# differ, the real store saw something the dry run didn't validate.
	local f scratch_etc="$STORE_SCRATCH_DIR$STORE_ETC_DIR"
	for f in policy/policy.35 contexts/files/file_contexts contexts/files/file_contexts.homedirs seusers; do
		if [ ! -f "$scratch_etc/$f" ]; then
			info "VERIFY FAIL: no dry-run copy of $f to compare against (was store-sync-dryrun run first?)"
			ok=0
			continue
		fi
		if ! sudo cmp -s "$scratch_etc/$f" "$STORE_ETC_DIR/$f"; then
			info "VERIFY FAIL: $f differs between the dry run and the real run -- they should be byte-identical (V1)"
			ok=0
		fi
	done
	# V3-lite: fc/homedir presence sanity (a full type-aware compare is
	# the CIL-vs-monolithic classifier this tool does not yet have --
	# Opus's review is explicit that gate_check.py is NOT it; flagged as
	# a follow-up, not silently skipped).
	[ -f "$STORE_ETC_DIR/contexts/files/file_contexts" ] || { info "VERIFY FAIL: no file_contexts after sync"; ok=0; }
	info "NOTE: this is a minimal verify pass (sesearch spot-check + module-set completeness + fc presence). Opus's full V1-V4 methodology (byte-identical dry-run-vs-real-run diff, the CIL-vs-monolithic classifier, contexts/ tree diff beyond files/) is NOT automated here yet -- run it by hand per review-store-sync-design.md before trusting this alone."
	[ "$ok" -eq 1 ]
}

store_write_marker() {
	mkdir -p "$(dirname "$STORE_MARKER")"
	{
		echo "synced_at=$(date -Iseconds)"
		echo "store_policy_kern_sha256=$(sudo sha256sum "$STORE_DIR/active/policy.kern" 2>/dev/null | cut -d' ' -f1)"
		echo "installed_policy_sha256=$(sha256_of "$INSTALLED_POLICY")"
		echo "commit_num=$(store_commit_num)"
	} > "$STORE_MARKER"
	info "wrote $STORE_MARKER"
}

die() {
	printf 'policy-cycle: ERROR: %s\n' "$*" >&2
	exit 1
}
info() { echo "policy-cycle: $*"; }

sha256_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

# Prints the count of non-comment/non-blank lines in booleans.local, or the
# literal string UNREADABLE if the file couldn't be read at all (permission
# error, I/O error, etc). The old `... || true` + `${var:-0}` idiom at both
# call sites (apply's step 8, finalize's check 4) collapsed BOTH "grep ran
# fine and found zero matches" (exit 1, expected) AND "grep couldn't even
# open the file" (exit 2, a real problem) down to the same "0" -- silently
# treating an unreadable booleans.local as if it had been verified empty
# (Opus's adversarial pass, 2026-09-27). Distinguish them explicitly.
store_booleans_local_status() {
	local path="$1" out status
	out="$(sudo grep -vc '^#\|^$' "$path" 2>/dev/null)" && status=0 || status=$?
	if [ "$status" -eq 0 ] || [ "$status" -eq 1 ]; then
		echo "${out:-0}"
	else
		echo "UNREADABLE"
	fi
}

# Runs `sediff --stats a b`, capturing its exit code and stderr instead of
# merging them into the diff text via `2>&1` -- the old pattern at every
# sediff call site treated "sediff itself crashed" (nonzero rc, stderr
# text) exactly like "sediff ran fine and found a real difference" (rc 0,
# nonempty stdout), so a transient failure (this box has hit apparent
# memory pressure running sediff against store-sized policies before) got
# reported and acted on as if it were a genuine policy divergence
# (Opus's spec, 2026-09-27).
#
# Sets SEDIFF_OUT as a side effect and returns:
#   0 = sediff ran fine, diff is empty (no difference) -- SEDIFF_OUT=""
#   1 = sediff ran fine, diff is non-empty -- SEDIFF_OUT has the diff
#   2 = sediff itself failed to run -- SEDIFF_OUT has an explanation +
#       its stderr. NOT a policy difference; callers must never treat
#       this the same as case 1. One automatic retry is attempted first
#       if the failure looks like a memory error.
# Callers must guard the call (e.g. `run_sediff_stats a b || rc=$?;
# rc=${rc:-0}`) since a nonzero return would otherwise trip `set -e`.
run_sediff_stats() {
	local a="$1" b="$2" out err rc attempt errfile
	errfile="$(mktemp "$STATE_DIR/sediff-stderr.XXXXXX")"
	for attempt in 1 2; do
		out="$(sediff --stats "$a" "$b" 2>"$errfile")" && rc=0 || rc=$?
		err="$(cat "$errfile" 2>/dev/null)"
		if [ "$rc" -eq 0 ]; then
			rm -f "$errfile"
			SEDIFF_OUT="$out"
			[ -z "$SEDIFF_OUT" ] && return 0
			return 1
		fi
		if [ "$attempt" -eq 1 ] && grep -qiE 'memoryerror|cannot allocate memory|out of memory' <<<"$err"; then
			info "sediff failed with an apparent out-of-memory error (rc=$rc) comparing $a vs $b -- retrying once before giving up: $err"
			continue
		fi
		break
	done
	rm -f "$errfile"
	SEDIFF_OUT="sediff itself FAILED (rc=$rc) comparing $a vs $b -- this is NOT a policy difference, do not treat it as one. stderr:
$err
If this looks like a memory error (MemoryError / cannot allocate memory), close other applications and retry, or run sediff by hand outside this script to confirm what's going on before assuming anything about the policy's actual state."
	return 2
}

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

die_if_store_synced() {
	# B6: once store-sync-apply succeeds, the store is authoritative and
	# modular. The monolithic build/gate/install/load path would silently
	# fight it (this exact bug is why tonight started) -- the gate would
	# also become permanently NON-ADDITIVE (CIL vs checkpolicy
	# representation), which is a correct result, not a bug to route
	# around. All of them just refuse once the marker exists.
	[ -f "$STORE_MARKER" ] && die "the store has been synced ($STORE_MARKER exists) -- '$1' is the monolithic path and is retired. Use the modular tools (semodule, or a future modular-aware subcommand here) instead."
	return 0
}

cmd_gate() {
	die_if_store_synced gate
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
	die_if_store_synced install
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
	die_if_store_synced load
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

cmd_store_sync_plan() {
	# Read-only. Never mutates anything -- safe to run and re-run freely.
	# Computes the actual foreign-module set live (the same computation
	# `make pure-load` does internally) and cross-checks it against the
	# hardcoded STORE_LEGACY_MODULES list from the 2026-09-26 audit, so
	# drift is caught here instead of inside a live transaction.
	[ -f "$STORE_MARKER" ] && info "NOTE: $STORE_MARKER already exists -- a sync may have already run, or it was created some other way."

	local foreign expected_sorted foreign_sorted
	foreign="$(store_foreign_modules)"
	expected_sorted="$(printf '%s\n' "${STORE_LEGACY_MODULES[@]}" | sort -u)"
	foreign_sorted="$(echo "$foreign" | sort -u)"

	info "live foreign-module set (semodule -l minus modules.conf's base+module entries):"
	echo "$foreign" | sed 's/^/  - /'
	echo

	if [ "$foreign_sorted" = "$expected_sorted" ]; then
		info "MATCHES the 2026-09-26 audit's 24-module list exactly -- safe to plan against."
	else
		info "DOES NOT MATCH the audit's list -- the store has drifted. diff (< expected, > live):"
		diff <(echo "$expected_sorted") <(echo "$foreign_sorted") || true
		info "store-sync-apply would refuse to run until this is reconciled."
	fi

	echo
	info "store-sync-apply (implemented, pending Opus's review before whitewhistle runs it for real) does, in order:"
	echo "  1. lock (flock, R6) + refuse if marker exists, pacman is running, or db.lck is present (R4)"
	echo "  2. backup ALL THREE trees: $STORE_DIR, $STORE_ETC_DIR, $STORE_USR_DIR"
	echo "     (tar --xattrs --xattrs-include='security.selinux' --acls, timestamped, content-verified,"
	echo "     RESTORE runbook written alongside the backup and copied to /root/ for console readability)"
	echo "  3. unprivileged modular build: 'make MONOLITHIC=n clean' first (B2 -- a stale monolithic"
	echo "     tmp/ silently poisons base.conf), then 'make MONOLITHIC=n all' (base.pp + every tree"
	echo "     module .pp), sha256 manifest of all of it pinned for step 6 to re-check"
	echo "  4. re-assert the live foreign-module set == the known 24 (shown above) -- abort if drifted"
	echo "  5. dry run: copy the live store+etc into a scratch dir, then the SAME pinned semodule argv"
	echo "     as step 6 with '-p <scratch> -N' added -- same mechanism as 'make validate'"
	echo "     (Rules.modular:229), zero live risk. Must succeed before step 6 runs for real."
	echo "  6. operator confirmation, then 'sudo setenforce 0', then the REAL run: a single pinned"
	echo "     'semodule -s $POLICY_NAME -i base.pp -i <every tree module.pp> -r <the 24> -N'"
	echo "     (default priority 400, matching the store's existing modules -- never -X 100, which"
	echo "     would be silently shadowed by the 428 stale priority-400 copies and change nothing)."
	echo "     Manifest re-checked immediately before this runs (B3's 'pin the bytes'). '-N' keeps this"
	echo "     an on-disk-only commit as an extra checkpoint; 'sudo load_policy' + a post-load sediff"
	echo "     check against \$RUNNING_POLICY (must be empty) then makes it live, same as 'cmd_load'."
	echo "  7. verify: module-set completeness, sesearch spot-check, fc presence (full V1-V4 -- byte-"
	echo "     identical dry-run-vs-real-run diff and the CIL-vs-monolithic classifier -- is manual"
	echo "     for now, per review-store-sync-design.md; not yet automated here)"
	echo "  8. 'sudo semanage boolean -D' (clear the store's 8 stale booleans.local entries --"
	echo "     booleans.conf already compiles all of them true, whitewhistle approved this), then"
	echo "     write $STORE_MARKER only if 1-7 all succeeded"
	echo "  Does NOT setenforce 1 at any point -- stays permissive until a verified reboot (R5)."
	echo "  Does NOT run 'sudo make pure-load' or 'sudo setsebool -P' -- both retracted in review"
	echo "  (pure-load's foreign-list comes from a shell-out that fails open to empty; setsebool -P"
	echo "  would pin booleans.local again, contradicting booleans.conf as the source of truth)."
}

cmd_store_sync_dryrun() {
	# S2: build + assertion + dry run + automatic checks. NO backup, NO
	# setenforce, NO live change of any kind -- reads the live store only
	# to copy it into a scratch dir. Safe for anyone (Opus included) to run
	# and re-run freely; not blocked by the hook, since it never calls
	# semodule/semanage/setsebool against the real store.
	echo "=== dryrun 1/4: unprivileged modular build ==="
	store_build_modular

	echo "=== dryrun 2/4: foreign-module assertion against the known 24 ==="
	local foreign_sorted expected_sorted
	foreign_sorted="$(store_foreign_modules | sort -u)"
	expected_sorted="$(printf '%s\n' "${STORE_LEGACY_MODULES[@]}" | sort -u)"
	if [ "$foreign_sorted" != "$expected_sorted" ]; then
		diff <(echo "$expected_sorted") <(echo "$foreign_sorted") || true
		die "live foreign-module set no longer matches the known 24 -- store has drifted. Refusing."
	fi
	info "foreign-module set matches exactly: ${STORE_LEGACY_MODULES[*]}"
	store_build_argv

	echo "=== dryrun 3/4: dry run (scratch copy of the real store, --noreload) ==="
	store_dry_run

	echo "=== dryrun 4/4: automatic checks ==="
	local ok=1
	local scratch_policy="$STORE_SCRATCH_DIR$STORE_ETC_DIR/policy/policy.35"
	[ -f "$scratch_policy" ] || die "dry run did not produce $scratch_policy"

	info "module count in the scratch store (expect $(store_tree_modules | wc -l)):"
	local scratch_count
	scratch_count="$(sudo semodule -s "$POLICY_NAME" -p "$STORE_SCRATCH_DIR" -l | wc -l)"
	echo "  got: $scratch_count"
	[ "$scratch_count" -eq "$(store_tree_modules | wc -l)" ] || { info "CHECK FAIL: module count mismatch"; ok=0; }

	info "V2 classifier (installed vs dry-run policy.35) -- see tools/store_sync_classify.py for what this checks:"
	local classify_out classify_verdict
	classify_out="$(python3 "$REPO/tools/store_sync_classify.py" "$INSTALLED_POLICY" "$scratch_policy")"
	classify_verdict="$(head -1 <<< "$classify_out")"
	echo "$classify_out"
	[ "$classify_verdict" = "PASS" ] || ok=0

	# V3 (Opus): everything the classifier doesn't cover because it isn't
	# in policy.35 at all -- contexts/ outside files/ (customizable_types,
	# etc.), file_contexts (alias-normalized), homedirs, seusers.
	local scratch_etc="$STORE_SCRATCH_DIR$STORE_ETC_DIR"

	info "V3: contexts/ outside contexts/files/ (customizable_types, etc.)"
	local ctx_diff
	ctx_diff="$(sudo diff -rq --exclude=files "$STORE_ETC_DIR/contexts" "$scratch_etc/contexts" 2>&1)"
	if [ -n "$ctx_diff" ]; then
		info "CHECK FAIL: contexts/ (outside files/) differs:"
		echo "$ctx_diff"
		ok=0
	else
		info "  identical"
	fi

	# Opus's dryrun #2 finding: this policy is non-MLS, so a context ends at
	# "...:type" with no trailing ":s0" -- the old ":[a-z_0-9]+_t:" regex
	# required a colon AFTER the type (implicitly assuming an MLS level)
	# and matched nothing, and under `set -euo pipefail` an empty grep in a
	# command substitution silently killed the whole subcommand. Extract
	# the type from the LAST whitespace field (context) by its 3rd colon
	# field instead -- works with or without an MLS suffix -- and skip
	# "<<none>>" contexts (no default assigned, not a real type).
	fc_ctx_type() { local ctx; ctx="$(awk '{print $NF}' <<<"$1")"; [ "$ctx" = "<<none>>" ] && return 1; cut -s -d: -f3 <<<"$ctx"; }
	fc_key() { awk '{NF--; print}' <<<"$1"; }  # everything except the context field
	# Opus's dryrun #3 finding: `seinfo -t A -x` prints A's alias-vs-primary
	# definition as ONE line ("type PRIMARY alias ALIAS1, ALIAS2, ...;"),
	# never a line consisting of just the other name -- so a `grep -qx`
	# for the other name can never match, in either direction. Querying
	# either an alias or its primary type returns the SAME line; take the
	# primary type name (the token right after "type") as the canonical
	# form and compare that instead of grepping for the other name.
	fc_canon_type() { seinfo -t "$1" -x "$INSTALLED_POLICY" 2>/dev/null | awk '$1=="type"{print $2; exit}'; }

	info "V3: file_contexts, whitespace-normalized set diff (alias swaps only, resolved via seinfo)"
	local fc_only_installed fc_only_scratch bad_fc_lines=()
	fc_only_installed="$(sudo awk '{$1=$1};1' "$STORE_ETC_DIR/contexts/files/file_contexts" | sort -u)"
	fc_only_scratch="$(sudo awk '{$1=$1};1' "$scratch_etc/contexts/files/file_contexts" | sort -u)"
	local removed_lines added_lines
	removed_lines="$(comm -23 <(echo "$fc_only_installed") <(echo "$fc_only_scratch"))"
	added_lines="$(comm -13 <(echo "$fc_only_installed") <(echo "$fc_only_scratch"))"
	if [ -z "$removed_lines$added_lines" ]; then
		info "  identical (0 differing lines)"
	else
		# Pair by key (everything but the context): an alias<->primary type
		# swap on the SAME path+filetype is fine if seinfo confirms the
		# alias relationship; anything else (a path only on one side, or a
		# real type change seinfo doesn't recognize as an alias pair) fails.
		local key old_type new_type old_line found
		while IFS= read -r line; do
			[ -z "$line" ] && continue
			key="$(fc_key "$line")"
			old_type="$(fc_ctx_type "$line")" || { bad_fc_lines+=("removed line has <<none>> or unparseable context: $line"); continue; }
			found=0
			while IFS= read -r cand; do
				[ -z "$cand" ] && continue
				[ "$(fc_key "$cand")" = "$key" ] || continue
				found=1
				old_line="$cand"
				break
			done <<< "$added_lines"
			if [ "$found" -eq 0 ]; then
				bad_fc_lines+=("removed, no corresponding added line for: $line")
				continue
			fi
			new_type="$(fc_ctx_type "$old_line")" || { bad_fc_lines+=("added line has <<none>> or unparseable context: $old_line"); continue; }
			if [ -z "$old_type" ] || [ -z "$new_type" ]; then
				bad_fc_lines+=("could not extract types to compare: $line")
				continue
			fi
			local old_canon new_canon
			old_canon="$(fc_canon_type "$old_type")"
			new_canon="$(fc_canon_type "$new_type")"
			if [ -z "$old_canon" ] || [ "$old_canon" != "$new_canon" ]; then
				bad_fc_lines+=("$old_type <-> $new_type on $key is not an alias pair per seinfo (canon: '$old_canon' vs '$new_canon')")
			fi
		done <<< "$removed_lines"

		# Opus's dryrun #3 fail-open: only removed_lines was walked, so a
		# path present ONLY in the dry run (no removed counterpart at all)
		# was never checked. Walk added_lines symmetrically, and also
		# require equal counts as a cheap independent cross-check.
		local removed_count added_count
		removed_count="$(grep -c . <<< "$removed_lines" || true)"
		added_count="$(grep -c . <<< "$added_lines" || true)"
		if [ "${removed_count:-0}" != "${added_count:-0}" ]; then
			bad_fc_lines+=("removed_lines has $removed_count entries but added_lines has $added_count -- not a 1:1 swap set")
		fi
		while IFS= read -r line; do
			[ -z "$line" ] && continue
			key="$(fc_key "$line")"
			found=0
			while IFS= read -r cand; do
				[ -z "$cand" ] && continue
				[ "$(fc_key "$cand")" = "$key" ] && { found=1; break; }
			done <<< "$removed_lines"
			[ "$found" -eq 1 ] || bad_fc_lines+=("added, no corresponding removed line for: $line")
		done <<< "$added_lines"

		if [ "${#bad_fc_lines[@]}" -gt 0 ]; then
			info "CHECK FAIL: file_contexts has unexplained differences:"
			printf '  %s\n' "${bad_fc_lines[@]}"
			ok=0
		else
			info "  $removed_count differing line(s), all confirmed alias<->primary-type swaps via seinfo"
		fi
	fi

	info "V3: file_contexts.homedirs -- scratch's type vocabulary must be a subset of installed's"
	local homedirs_types_installed homedirs_types_scratch extra_types
	# Skip comment/blank lines before extracting -- otherwise `cut -d: -f3`
	# on a delimiter-less line (a comment) echoes the WHOLE line back
	# unchanged (GNU cut's default when -s isn't given), polluting the
	# type set with garbage that isn't a type at all.
	homedirs_types_installed="$(sudo grep -vE '^\s*(#|$)' "$STORE_ETC_DIR/contexts/files/file_contexts.homedirs" 2>/dev/null | awk '{print $NF}' | grep -v '^<<none>>$' | cut -s -d: -f3 | sort -u)"
	homedirs_types_scratch="$(sudo grep -vE '^\s*(#|$)' "$scratch_etc/contexts/files/file_contexts.homedirs" 2>/dev/null | awk '{print $NF}' | grep -v '^<<none>>$' | cut -s -d: -f3 | sort -u)"
	extra_types="$(comm -23 <(echo "$homedirs_types_scratch") <(echo "$homedirs_types_installed"))"
	if [ -n "$extra_types" ]; then
		info "CHECK FAIL: homedirs uses type(s) not present in the installed homedirs: $extra_types"
		ok=0
	else
		info "  OK (no new types, per-user role blocks aside)"
	fi

	info "V3: seusers"
	if sudo cmp -s "$STORE_ETC_DIR/seusers" "$scratch_etc/seusers"; then
		info "  identical"
	else
		info "CHECK FAIL: seusers differs"
		sudo diff "$STORE_ETC_DIR/seusers" "$scratch_etc/seusers" || true
		ok=0
	fi

	echo
	if [ "$ok" -eq 1 ]; then
		info "DRYRUN CHECKS: PASS -- safe for a human (or Opus) to review this output before 'store-sync-apply' is run for real."
	else
		info "DRYRUN CHECKS: FAIL -- see reasons above. Do not proceed to store-sync-apply until these are understood and resolved."
	fi
	[ "$ok" -eq 1 ]
}

cmd_store_sync_apply() {
	# Implements Opus's 2026-09-26 store-sync-design review (B1-B6, R1-R6,
	# V1-V4 -- ~/claude-readme/opus-5-5/review-store-sync-design.md).
	# NOT reviewed live end-to-end yet: written to be run by whitewhistle
	# directly in a terminal (R3 -- the 600s Bash-tool timeout is a real
	# risk for a privileged, possibly-slow commit), after Opus reviews this
	# script itself, same process as every other change tonight.
	[ "$(id -u)" -eq 0 ] && die "run this as your normal user (with sudo available), not as root -- ownership assumptions in the backup step rely on it."
	command -v flock >/dev/null || die "flock not found"

	mkdir -p "$STATE_DIR"
	exec 9>"$STORE_LOCK_FILE"
	flock -n 9 || die "another store-sync-apply (or something holding $STORE_LOCK_FILE) is already running -- R6: mutual exclusion while this runs."

	[ -f "$STORE_MARKER" ] && die "already synced ($STORE_MARKER exists). Delete it by hand first if you deliberately want to re-run this -- it is not done automatically."

	# R4: pacman precondition. Its selinux-refpolicy-{arch,git} scriptlets
	# call semodule -i without --noreload; a concurrent transaction could
	# live-load an unrelated, ungated policy mid-sync.
	pgrep -x pacman >/dev/null 2>&1 && die "pacman is currently running -- wait for it to finish first (R4)."
	[ -f /var/lib/pacman/db.lck ] && die "pacman db.lck is present -- a transaction may be mid-flight or crashed. Resolve that before syncing (R4)."

	echo "=== 1/8: pre-state ==="
	local pre_commit
	pre_commit="$(store_commit_num)"
	info "pre-sync commit_num=$pre_commit, enforce=$(getenforce)"

	echo "=== 2/8: backup (var/lib, etc, usr/share) ==="
	store_backup_all pre-sync

	echo "=== 3/8: unprivileged modular build (MONOLITHIC=n clean first -- B2) ==="
	store_build_modular

	echo "=== 4/8: foreign-module assertion against the known 24 ==="
	local foreign_sorted expected_sorted
	foreign_sorted="$(store_foreign_modules | sort -u)"
	expected_sorted="$(printf '%s\n' "${STORE_LEGACY_MODULES[@]}" | sort -u)"
	if [ "$foreign_sorted" != "$expected_sorted" ]; then
		echo "$foreign_sorted" > "$STATE_DIR/store-sync-foreign-live.txt"
		echo "$expected_sorted" > "$STATE_DIR/store-sync-foreign-expected.txt"
		diff "$STATE_DIR/store-sync-foreign-expected.txt" "$STATE_DIR/store-sync-foreign-live.txt" || true
		die "live foreign-module set no longer matches the known 24 (diff above) -- store has drifted since the audit. Refusing. Re-run 'store-sync-plan' first."
	fi
	info "foreign-module set matches exactly: ${STORE_LEGACY_MODULES[*]}"

	# S3: build the pinned argv exactly once, right here, from the
	# assertion just made -- both the dry run and the real run reuse this
	# same array (and re-verify its sha), never re-querying semodule -l.
	store_build_argv

	echo "=== 5/8: dry run (scratch copy of the real store, --noreload, zero live risk) ==="
	store_dry_run

	local dryrun_classify dryrun_verdict
	dryrun_classify="$(python3 "$REPO/tools/store_sync_classify.py" "$INSTALLED_POLICY" "$STORE_SCRATCH_DIR$STORE_ETC_DIR/policy/policy.35")"
	dryrun_verdict="$(head -1 <<< "$dryrun_classify")"
	echo "$dryrun_classify"
	[ "$dryrun_verdict" = "PASS" ] || die "dry-run classifier verdict is $dryrun_verdict (see reasons above) -- refusing to proceed to the real run. Run 'store-sync-dryrun' separately to investigate without any live risk."

	echo "=== 6/8: setenforce 0, then the REAL run -- this is the live, privileged commit ==="
	echo "About to set the system Permissive and run the pinned semodule commit against the REAL store."
	echo "Pre-sync commit_num=$pre_commit. This will remove: ${STORE_LEGACY_MODULES[*]}"
	read -r -p "Type 'yes' to proceed, anything else aborts: " confirm
	[ "$confirm" = "yes" ] || die "aborted by operator before the real run -- nothing live was touched."
	sudo setenforce 0
	[ "$(getenforce)" = "Permissive" ] || die "setenforce 0 did not take effect (getenforce reports $(getenforce)) -- refusing to proceed with the real run while Enforcing."
	store_real_run

	echo "=== 7/8: verify ==="
	if ! store_verify_after_sync "$pre_commit"; then
		die "VERIFICATION FAILED after the real run -- system is in an uncertain state. Do NOT setenforce 1. See the RESTORE runbook printed in step 2 (also under $STORE_BACKUP_DIR). Marker NOT written."
	fi

	echo "=== 8/8: clear booleans.local, write marker ==="
	# whitewhistle-approved: booleans.conf already compiles all 10 true in
	# the modular build (confirmed: seinfo -b NAME -x base.pp/module .pp),
	# so the store's 8 stale booleans.local overrides are now redundant
	# and, per the git-is-source-of-truth decision, should go.
	# S5 (fixed): the original check asserted policy.35's sha256 stayed
	# byte-identical across 'semanage boolean -D'. That's wrong -- libsepol
	# can (and did, on the real run) lay out policy.35 differently for an
	# empty vs. a populated booleans.local even when every boolean's
	# compiled default is unchanged (Opus: same-size file, 813k bytes
	# differing, zero semantic change). Compare semantically instead: a
	# full sediff between the pre-clear and post-clear installed policy
	# must show nothing at all (booleans.local was redundant -- its 8
	# entries already equalled the tree's compiled defaults, so clearing
	# it should change zero effective state), and boolean defaults are
	# read from the compiled policy itself (`seinfo -b NAME -x`), never
	# from `getsebool` -- getsebool reports the kernel's current runtime
	# value, which survives a reload and would still read correctly even
	# if the compiled default silently reverted.
	local pre_clear_copy="$STATE_DIR/pre-boolean-clear-policy.35"
	cp "$INSTALLED_POLICY" "$pre_clear_copy"
	sudo semanage boolean -D

	local booleans_local_path b rc
	run_sediff_stats "$RUNNING_POLICY" "$INSTALLED_POLICY" || rc=$?
	rc="${rc:-0}"
	case "$rc" in
		2) die "post-'semanage boolean -D' sediff check could not complete -- do NOT write the marker: $SEDIFF_OUT" ;;
		1) die "post-'semanage boolean -D' sediff is NOT empty -- running policy does not match installed:
$SEDIFF_OUT" ;;
	esac
	run_sediff_stats "$pre_clear_copy" "$INSTALLED_POLICY" || rc=$?
	rc="${rc:-0}"
	rm -f "$pre_clear_copy"
	case "$rc" in
		2) die "post-'semanage boolean -D' pre/post comparison could not complete -- do NOT write the marker: $SEDIFF_OUT" ;;
		1) die "installed policy.35 has a real semantic difference after 'semanage boolean -D' (sediff --stats below) -- expected none, since all 8 cleared booleans.local entries were supposed to already equal their compiled defaults. Do NOT write the marker; investigate before retrying:
$SEDIFF_OUT" ;;
	esac
	for b in "${STORE_INTENDED_TRUE_BOOLEANS[@]}"; do
		seinfo -b "$b" -x "$INSTALLED_POLICY" 2>/dev/null | grep -q "^   bool $b true;$" \
			|| die "$b's compiled default in the installed policy.35 is not 'true' after clearing booleans.local. Do NOT write the marker."
	done
	seinfo -b allow_execmod -x "$INSTALLED_POLICY" 2>/dev/null | grep -q "^   bool allow_execmod false;$" \
		|| die "allow_execmod's compiled default in the installed policy.35 is not 'false' after clearing booleans.local. Do NOT write the marker."
	booleans_local_path="$(sudo find "$STORE_DIR" -maxdepth 3 -iname booleans.local 2>/dev/null | head -1)"
	if [ -n "$booleans_local_path" ]; then
		local remaining_booleans
		remaining_booleans="$(store_booleans_local_status "$booleans_local_path")"
		[ "$remaining_booleans" != "UNREADABLE" ] \
			|| die "could not read booleans.local ($booleans_local_path) to verify it's empty after 'semanage boolean -D' -- treating as unverified, not safe to assume empty. Do NOT write the marker."
		[ "$remaining_booleans" -eq 0 ] || die "booleans.local ($booleans_local_path) is not empty after 'semanage boolean -D' ($remaining_booleans entries remain). Do NOT write the marker."
	fi
	info "post-clear verify OK: running==installed, policy.35 unchanged, all 10 booleans at their compiled defaults, booleans.local empty"

	store_write_marker

	info "Sync complete. Store commit_num: $(store_commit_num) (was $pre_commit)."
	info "System remains Permissive by design -- do NOT setenforce 1 until after a verified reboot (R5). The monolithic build/gate/install/load subcommands are now retired (they die when $STORE_MARKER exists)."
}

# store-sync-finalize: for the specific situation where a real sync already
# succeeded (commit_num advanced, everything on disk/live is correct) but
# the marker was never written because a LATER check in cmd_store_sync_apply
# died on a false positive (the original S5 bug: 2026-09-26 night, real
# commit_num 53->55, marker absent). This is deliberately NOT "re-run
# apply" -- a real re-run would die at its own step 4 (foreign-module
# assertion), since the 24 legacy modules are already gone; that's the
# whole point, the sync already happened. Instead this independently
# re-derives every fact apply's own verification relies on, straight from
# the CURRENT live state, and writes the marker only if every single one
# checks out. Read-only apart from the marker write itself -- no semodule,
# no semanage, no setsebool anywhere in this function (Opus's checklist
# point 7; a structural property of this code, not something it asserts
# about itself at runtime).
cmd_store_sync_finalize() {
	# --dry-run: run every check and print the verdict, but never call
	# store_write_marker. Added after an incident (2026-09-27) where running
	# this command to sanity-check its own check output ended up writing the
	# real marker, because the function had no way to observe its checks
	# without also taking the one live action it gates -- there was no
	# side-effect-free path through it at all. Model: same idea as
	# store-sync-apply's own dry run (observe, take zero live action), even
	# though the mechanism differs (apply's dry run executes against a
	# scratch copy of the store; finalize's dry run just skips its own
	# final write, since every check it runs is already read-only).
	local dry_run=0
	case "${1:-}" in
		--dry-run) dry_run=1; shift ;;
		"") ;;
		# Opus's adversarial pass, 2026-09-27: an unrecognized arg (a typo
		# like --dryrun) used to fall straight through to a REAL run --
		# exactly the failure mode --dry-run exists to prevent. Refuse
		# instead of guessing.
		*) die "store-sync-finalize: unrecognized argument '$1' -- the only accepted flag is --dry-run" ;;
	esac

	[ "$(id -u)" -eq 0 ] && die "run this as your normal user (with sudo available), not as root."
	command -v flock >/dev/null || die "flock not found"

	mkdir -p "$STATE_DIR"
	exec 9>"$STORE_LOCK_FILE"
	flock -n 9 || die "another store-sync-apply/finalize (or something holding $STORE_LOCK_FILE) is already running."

	if [ -f "$STORE_MARKER" ]; then
		info "marker already exists ($STORE_MARKER) -- already finalized, nothing to do (a second run, dry or real, is a safe no-op):"
		cat "$STORE_MARKER"
		return 0
	fi

	if [ "$dry_run" -eq 1 ]; then
		info "=== store-sync-finalize --dry-run: re-verifying the CURRENT live state (checks only -- marker will NOT be written) ==="
	else
		info "=== store-sync-finalize: re-verifying the CURRENT live state, writing the marker only if every check passes ==="
	fi
	local ok=1 sec_ok scratch_etc="$STORE_SCRATCH_DIR$STORE_ETC_DIR"

	echo "=== 1/6: running policy == installed policy (sediff) ==="
	sec_ok=1
	local rc
	run_sediff_stats "$RUNNING_POLICY" "$INSTALLED_POLICY" || rc=$?
	rc="${rc:-0}"
	case "$rc" in
		2) info "FAIL: sediff check could not complete: $SEDIFF_OUT"; sec_ok=0 ;;
		1) info "FAIL: running policy differs from installed:
$SEDIFF_OUT"; sec_ok=0 ;;
	esac
	[ "$sec_ok" -eq 1 ] && info "OK: running == installed"
	ok=$((ok & sec_ok))

	echo "=== 2/6: dry-run scratch reference policy.35 vs installed (sediff, semantic -- NOT cmp/sha, per the S5 lesson: booleans.local's presence/absence alone changes policy.35's bytes with zero semantic effect) ==="
	sec_ok=1
	local scratch_policy="$scratch_etc/policy/policy.35"
	if [ ! -f "$scratch_policy" ]; then
		info "FAIL: no dry-run scratch copy at $scratch_policy -- was store-sync-dryrun/apply ever run against this checkout? Cannot cross-check without it."
		sec_ok=0
	else
		run_sediff_stats "$scratch_policy" "$INSTALLED_POLICY" || rc=$?
		rc="${rc:-0}"
		case "$rc" in
			2) info "FAIL: sediff check could not complete: $SEDIFF_OUT"; sec_ok=0 ;;
			1) info "FAIL: dry-run scratch policy.35 differs semantically from installed:
$SEDIFF_OUT"; sec_ok=0 ;;
		esac
	fi
	[ "$sec_ok" -eq 1 ] && info "OK: scratch policy.35 matches installed semantically"
	ok=$((ok & sec_ok))

	echo "=== 3/6: module set == tree modules exactly, both directions (no foreign/legacy left, nothing tree missing) ==="
	sec_ok=1
	local foreign installed_sorted tree_sorted missing_tree installed_count tree_count
	foreign="$(store_foreign_modules)"
	if [ -n "$foreign" ]; then
		info "FAIL: foreign/legacy modules still present: $foreign"
		sec_ok=0
	fi
	installed_sorted="$(sudo semodule -l | sort -u)"
	tree_sorted="$(store_tree_modules | sort -u)"
	missing_tree="$(comm -23 <(echo "$tree_sorted") <(echo "$installed_sorted"))"
	if [ -n "$missing_tree" ]; then
		info "FAIL: tree modules missing from the store: $missing_tree"
		sec_ok=0
	fi
	installed_count="$(echo "$installed_sorted" | wc -l)"
	tree_count="$(echo "$tree_sorted" | wc -l)"
	if [ "$installed_count" != "$tree_count" ]; then
		info "FAIL: installed module count ($installed_count) != tree module count ($tree_count) -- something extra beyond what the checks above caught"
		sec_ok=0
	fi
	[ "$sec_ok" -eq 1 ] && info "OK: module set is exactly the tree's ($installed_count modules)"
	ok=$((ok & sec_ok))

	echo "=== 4/6: booleans.local is empty or absent, and compiled boolean defaults (seinfo -b -x against installed policy.35 -- never getsebool, which reports the kernel's current runtime value, not the compiled default) ==="
	sec_ok=1
	local booleans_local_path remaining_booleans b
	booleans_local_path="$(sudo find "$STORE_DIR" -maxdepth 3 -iname booleans.local 2>/dev/null | head -1)"
	if [ -n "$booleans_local_path" ]; then
		remaining_booleans="$(store_booleans_local_status "$booleans_local_path")"
		if [ "$remaining_booleans" = "UNREADABLE" ]; then
			info "FAIL: could not read booleans.local ($booleans_local_path) to verify it's empty -- treating as unverified, not safe to assume empty"
			sec_ok=0
		elif [ "$remaining_booleans" -ne 0 ]; then
			info "FAIL: booleans.local ($booleans_local_path) has $remaining_booleans entries, expected 0"
			sec_ok=0
		fi
	fi
	for b in "${STORE_INTENDED_TRUE_BOOLEANS[@]}"; do
		seinfo -b "$b" -x "$INSTALLED_POLICY" 2>/dev/null | grep -q "^   bool $b true;$" \
			|| { info "FAIL: $b's compiled default is not 'true'"; sec_ok=0; }
	done
	seinfo -b allow_execmod -x "$INSTALLED_POLICY" 2>/dev/null | grep -q "^   bool allow_execmod false;$" \
		|| { info "FAIL: allow_execmod's compiled default is not 'false'"; sec_ok=0; }
	[ "$sec_ok" -eq 1 ] && info "OK: booleans.local empty/absent, all 10 compiled defaults correct"
	ok=$((ok & sec_ok))

	echo "=== 5/6: file_contexts / file_contexts.homedirs / seusers byte-equal to the dry-run scratch copy (plain cmp is fine here -- unlike policy.35, these aren't affected by booleans.local) ==="
	sec_ok=1
	local f
	for f in contexts/files/file_contexts contexts/files/file_contexts.homedirs seusers; do
		if [ ! -f "$scratch_etc/$f" ]; then
			info "FAIL: no dry-run scratch copy of $f to compare against"
			sec_ok=0
			continue
		fi
		sudo cmp -s "$scratch_etc/$f" "$STORE_ETC_DIR/$f" \
			|| { info "FAIL: $f differs from the dry-run scratch copy"; sec_ok=0; }
	done
	[ "$sec_ok" -eq 1 ] && info "OK: fc/homedirs/seusers byte-identical to the dry-run scratch copy"
	ok=$((ok & sec_ok))

	echo
	[ "$ok" -eq 1 ] || die "store-sync-finalize found real problems (FAIL lines above). Marker NOT written. Investigate before retrying -- do not re-run this blindly hoping it clears."

	if [ "$dry_run" -eq 1 ]; then
		info "=== 6/6 (skipped -- --dry-run): all 5 checks passed. Marker would be written now. Nothing was written. Re-run without --dry-run to actually finalize. ==="
		return 0
	fi

	echo "=== 6/6: all checks passed -- writing marker ==="
	store_write_marker
	info "Store commit_num: $(store_commit_num). System remains Permissive by design -- do NOT setenforce 1 until after a verified reboot (R5). The monolithic build/gate/install/load subcommands are now retired (they die when $STORE_MARKER exists)."
}

case "${1:-}" in
	build) shift; cmd_build "$@" ;;
	gate) shift; cmd_gate "$@" ;;
	install) shift; cmd_install "$@" ;;
	load) shift; cmd_load "$@" ;;
	verify) shift; cmd_verify "$@" ;;
	verify-bool) shift; cmd_verify_bool "$@" ;;
	commit) shift; cmd_commit "$@" ;;
	store-sync-plan) shift; cmd_store_sync_plan "$@" ;;
	store-sync-dryrun) shift; cmd_store_sync_dryrun "$@" ;;
	store-sync-apply) shift; cmd_store_sync_apply "$@" ;;
	store-sync-finalize) shift; cmd_store_sync_finalize "$@" ;;
	*)
		echo "usage: policy-cycle.sh {build|gate|install|load|verify <sesearch-args>|verify-bool <name>|commit|store-sync-plan|store-sync-dryrun|store-sync-apply|store-sync-finalize [--dry-run]}"
		exit 1
		;;
esac
