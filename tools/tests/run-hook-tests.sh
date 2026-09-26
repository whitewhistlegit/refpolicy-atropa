#!/bin/bash
# Hook block/allow matrix for check-bash.sh / check_bash.py (written by Opus during review).
#   usage: run-hook-tests.sh <path/to/check-bash.sh>
# DENY = hook must block. load_policy expectations are computed from the CURRENT gate
# state (independently of the hook): allow only if Enforcing is off, or the gate stamp
# says ADDITIVE and its policy/running sha256 match the installed/running policy.
H=${1:?hook}; fail=0
STAMP=/home/whitewhistle/Atropa-Full/atropa-addons/refpolicy-atropa/tools/.state/gate-verdict
lp=DENY
if [ "$(getenforce)" != Enforcing ]; then lp=allow
elif [ -f "$STAMP" ] && grep -qx 'verdict=ADDITIVE' "$STAMP" \
  && [ "$(grep '^policy_sha256=' "$STAMP" | cut -d= -f2)" = "$(sha256sum /etc/selinux/atropa-refpolicy/policy/policy.35 | cut -d' ' -f1)" ] \
  && [ "$(grep '^running_sha256=' "$STAMP" | cut -d= -f2)" = "$(sha256sum /sys/fs/selinux/policy | cut -d' ' -f1)" ]; then lp=allow; fi
echo "(gate state => load_policy expected: $lp)"
run() { exp=$1; shift; j=$(python3 -c 'import json,sys; print(json.dumps({"tool_name":"Bash","tool_input":{"command":sys.argv[1]}}))' "$*")
  err=$(printf '%s' "$j" | bash "$H" 2>&1 >/dev/null); rc=$?
  got=allow; [ $rc -eq 2 ] && got=DENY
  if [ "$got" = "$exp" ]; then ok=PASS; else ok=FAIL; fail=1; fi
  printf '%-4s exp=%-5s got=%-5s reason=%-3s %s\n' $ok $exp $got "$([ $rc -eq 2 ] && { [ -n "$err" ] && echo yes || echo NO; } || echo -)" "$*"; }
echo "--- round-1 matrix"
run DENY  'semanage permissive -a brave_t'
run DENY  'sudo setsebool -P allow_execmod on'
run DENY  '/usr/sbin/setsebool -P allow_execmod on'
run DENY  'sudo setsebool allow_execmod on'
run allow 'semodule -l'
run DENY  'semodule -l && sudo semodule -i foo.pp'
run DENY  'sudo /usr/sbin/semodule -i foo.pp'
run $lp   'sudo load_policy'
run $lp   'sudo /usr/sbin/load_policy'
run DENY  'sudo make MONOLITHIC=y TYPE=standard SYSTEMD=y load'
run DENY  'sudo make DONTAUDIT=n MONOLITHIC=y TYPE=standard SYSTEMD=y load'
run DENY  'pkill -f brave'
run DENY  '/usr/bin/pkill -f brave'
run allow 'ls -la /etc/selinux'
run allow 'git commit -m "document why semanage was not used"'
echo "--- round-2: shell keywords, grouping, wrappers, sudo flags"
run DENY  'for m in a b; do sudo semodule -r $m; done'
run DENY  'if true; then sudo semodule -i foo.pp; fi'
run $lp   'for i in 1; do sudo load_policy; done'
run DENY  '(sudo semodule -i foo.pp)'
run DENY  'echo $(sudo semodule -i foo.pp)'
run DENY  'sleep 1 & sudo semodule -i foo.pp'
run DENY  'timeout 60 sudo semodule -i foo.pp'
run DENY  'nice -n 10 semodule -i foo.pp'
run DENY  'env FOO=1 semodule -i foo.pp'
run DENY  'sudo -r sysadm_r -t sysadm_t semodule -i foo.pp'
run DENY  'sudo -n setsebool -P allow_execmod on'
run DENY  'bash -c "sudo semodule -i foo.pp"'
run allow 'for f in a b; do echo $f; done'
run allow 'sudo -n sesearch -A -s aide_t /sys/fs/selinux/policy'
exit $fail
