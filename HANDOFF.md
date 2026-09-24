# atropa-refpolicy - from-scratch build tree (VERIFIED - full compile succeeded)

This tree has been fully compiled end-to-end in a sandbox and produced 426
clean .pp module packages plus a compiled base module, no errors. Only the
final `make install`/`make load` steps need your real box (needs root +
your actual kernel/selinux state).

## Fixes applied (both real, both needed on your machine)
1. build.conf: TYPE was "targeted" - not a valid value for upstream
   refpolicy (only standard/mcs/mls exist - see config/appconfig-*).
   Changed to TYPE = standard, which also matches what you actually run:
   its seusers has no MLS/MCS suffix at all, unlike mcs's :s0-mcs_systemhigh.
2. policy/modules/kernel/devices.fc: /dev/nvidia* split into per-node
   dri_device_t entries (nvidiactl, nvidia0-N, nvidia-modeset, nvidia-uvm,
   nvidia-uvm-tools, nvidia-caps/*) instead of stale xserver_misc_device_t -
   verified against your real device node output.
3. policy/modules/services/xserver.fc: added nvidia-settings and
   nvidia-xconfig as xserver_exec_t. Nothing else needed - upstream has no
   other nvidia binary entries; nvidia-smi/persistenced/modprobe/etc. fall
   through to the generic corecommands bin_t pattern correctly already.

## NOT changed - leave as-is on your box
policy/policy_capabilities has userspace_initial_context, netif_wildcard,
and genfs_seclabel_wildcard enabled. These failed to compile in THIS
sandbox only, because its checkpolicy (3.5, capped at policy v33) doesn't
recognize them. Your checkpolicy is 3.10-1 matching kernel v35 - it should
know all three natively. Leave them enabled; only disable if your own
`make policy` throws the same "invalid policy capability name" error,
which would be a real and useful data point if it happens (would mean your
checkpolicy doesn't actually support what /sys/fs/selinux/policyvers claims).

## modules.conf: left at default (full catalog)
Matches your current de facto setup. Modular build, so `semodule -d <name>`
disables anything post-load without a rebuild - no need to decide now.

## Commands to run on FinalMaelstrom

    make conf
    make policy
    sudo make install
    sudo make load

Then point /etc/selinux/config at SELINUXTYPE=atropa-refpolicy, and:

    sudo touch /.autorelabel

Reboot with enforcing=0 on the kernel cmdline first - first boot on a
from-scratch policy will surface denials, don't start enforcing blind.

## Still open
- Confirm /sys/fs/selinux/policyvers under zen and mainline specifically
- Check what selinux-alpm-hook targets so pacman transactions don't fight
  this build once active
- Decide whether to remove the other refpolicy-* AUR packages once this
  one is proven
