#!/bin/bash
# Gate regression harness for tools/policy-cycle.sh (written by Opus during review).
# Builds throwaway variants of a git revision in a scratch dir and runs the
# script's `gate` on each. Never installs or loads anything.
#   usage: run-gate-tests.sh <refpolicy-repo> <rev> [workdir]
# Requires: the running policy == <rev>'s policy (otherwise "base" won't be ADDITIVE).
set -u
REPO=${1:?repo}; REV=${2:?rev}; W=${3:-$(mktemp -d)}
mkdir -p "$W"; rm -rf "$W"/base "$W"/v_* "$W"/p_*
mkdir -p "$W/base"
if [ "$REV" = WORKTREE ]; then   # HEAD + uncommitted tracked changes, no writes to the repo
  git -C "$REPO" archive HEAD | tar -x -C "$W/base"
  git -C "$REPO" diff --name-only HEAD | while read -r f; do cp -a "$REPO/$f" "$W/base/$f"; done
else git -C "$REPO" archive "$REV" | tar -x -C "$W/base"; fi
cd "$W"
mk() { cp -a base "$1"; }
# expected verdicts
declare -A EXP=( [base]=ADDITIVE [v_add]=ADDITIVE [v_rm]=NON-ADDITIVE [v_bool]=NON-ADDITIVE
  [v_tt]=NON-ADDITIVE [v_fc]=NON-ADDITIVE [v_home]=NON-ADDITIVE [v_con]=NON-ADDITIVE [v_pipe]=NON-ADDITIVE )
mk v_add;  echo 'allow aide_t self:capability sys_nice;' >> v_add/policy/modules/admin/aide.te
mk v_rm;   sed -i 's/allow kernel_t self:capability2 { block_suspend checkpoint_restore };/allow kernel_t self:capability2 checkpoint_restore;/' v_rm/policy/modules/kernel/kernel.te
mk v_bool; sed -i 's/^aide_mmap_files = true/aide_mmap_files = false/' v_bool/policy/booleans.conf
mk v_tt;   printf '\ntype_transition aide_t tmp_t:file aide_log_t;\n' >> v_tt/policy/modules/admin/aide.te
mk v_fc;   printf '/usr/share/opus-gate-test(/.*)?\t--\tgen_context(system_u:object_r:xsession_exec_t,s0)\n' >> v_fc/policy/modules/services/xserver.fc
mk v_home; printf 'HOME_DIR/\\.opus-gate-test(/.*)?\t\tgen_context(system_u:object_r:user_home_t,s0)\n' >> v_home/policy/modules/apps/brave.fc
mk v_con;  printf '\nconstrain file { write } ( t1 != aide_t );\n' >> v_con/policy/constraints
mk v_pipe; cp v_rm/policy/modules/kernel/kernel.te v_pipe/policy/modules/kernel/kernel.te
           printf '\ndontaudit aide_t file_type:file { write setattr };\ndontaudit aide_t file_type:dir { write setattr };\n' >> v_pipe/policy/modules/admin/aide.te
# Build each variant EXACTLY the way the script's own `build` does (minus sudo), so
# build-flow bugs (e.g. stale file_contexts) are exercised too. Uses the variant's own
# copy of tools/policy-cycle.sh, with cmd_build's make lines extracted.
for v in base v_*; do
  ( cd "$v" && make clean >/dev/null 2>&1
    awk '/^cmd_build\(\)/,/^}/' tools/policy-cycle.sh | grep -oE '^\s*(sudo )?make [^>]*' | sed -E 's/^\s*(sudo )?make //' | grep -v '^clean\b\|[[:space:]]clean\b' | while read -r args; do make $args >/dev/null 2>&1; done
    echo "$v build rc=$?" ) &
done; wait
fail=0
for v in base v_*; do
  mkdir -p "$v/tools/.state"; printf 'head=x\n' > "$v/tools/.state/build-stamp"
  got=$(bash "$v/tools/policy-cycle.sh" gate 2>&1 | grep -oE 'VERDICT: [A-Z-]+' | cut -d' ' -f2)
  if [ "$got" = "${EXP[$v]}" ]; then ok=PASS; else ok=FAIL; fail=1; fi
  printf '%-4s %-7s expected=%-13s got=%s\n' "$ok" "$v" "${EXP[$v]}" "$got"
done
# Pairwise cases: call the rev's gate_check.py on two scratch builds directly
# (lets us test transitions the running policy can't provide).
GC="$W/base/tools/gate_check.py"
if [ -f "$GC" ]; then
  cp -a base p_perm; echo 'permissive aide_t;' >> p_perm/policy/modules/admin/aide.te
  cp -a base p_prop; sed -i 's/^UNK_PERMS = .*/UNK_PERMS = reject/' p_prop/build.conf
  for v in p_perm p_prop; do (cd $v && make MONOLITHIC=y TYPE=standard SYSTEMD=y clean >/dev/null 2>&1; make MONOLITHIC=y TYPE=standard SYSTEMD=y policy.35 >/dev/null 2>&1) & done; wait
  pair() { exp=$1; a=$2; b=$3; label=$4; got=$(python3 "$GC" "$a/policy.35" "$b/policy.35" | head -1)
    if [ "$got" = "$exp" ]; then ok=PASS; else ok=FAIL; fail=1; fi
    printf '%-4s %-26s expected=%-13s got=%s\n' "$ok" "$label" "$exp" "$got"; }
  pair ADDITIVE     base   p_perm "pair: permissive added"
  pair NON-ADDITIVE p_perm base   "pair: permissive removed"
  pair NON-ADDITIVE base   p_prop "pair: handle_unknown->reject"
fi
exit $fail
