#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
MODE="${1:---dry-run}"
[[ "${2:-}" == --state ]] || { echo 'usage: phk1_one_fk_recover_remote.sh --dry-run|--execute --state DIR' >&2; exit 2; }
STATE="${3:-}"
ROOT="$HOME/civiclight-testbench/phk1-ops"
LOG_AUDIT="$ROOT/tools/phk1_log_events.py"
BRIDGE="$HOME/civiclight-testbench/bin/sqrl_bridge_rawjtag_coe"
LIBS="$HOME/civiclight-testbench/compat_libs"
CANARY_USB=153300000957
CANARY_JTAG=153300000957A
PEER_USB=153300000711
PHK_SHA=47a392b76ebdfdd9edbfc5270f21b48fb6d1acb73e45a7425811865a196d76f8
XBT_SHA=f9812864d13a6963700f60709507ff85ee660fb77e846e51be533b2d479502df
PHK="$ROOT/candidates/PHK1_USER1_TCK_READCLK_RESPONSE_VALID_REFILL_20261103/47a392b76ebd/image/PHK1_USER1_TCK_READCLK_RESPONSE_VALID_REFILL_20261103.bit"
XBT="$HOME/fk33-prl-pod/artifacts/XBT_V4P1.bit"
CANDIDATE_DIR="$ROOT/candidates/PHK1_USER1_TCK_READCLK_RESPONSE_VALID_REFILL_20261103/47a392b76ebd"
ROLLBACK_BINDING="$CANDIDATE_DIR/metadata/xbt-rollback-binding.json"
PORT=22110; XVCPORT=2542
CLAIM_DIR="$HOME/.local/state/project-sidecar-arbiter/claims"
CLAIM_0711="$CLAIM_DIR/0711.claim"
CLAIM_0957="$CLAIM_DIR/0957.claim"
BRIDGE_UNIT=project-sidecar-fallback-testbench-bridge.service
CANARY_UNIT=project-sidecar-fallback-0711.service
PEER_UNIT=project-sidecar-fallback-0957.service
REC_CANARY=fk33-prl-pod-0957-eight-recovery.service
REC_PEER=fk33-prl-pod-0711-v2-recovery.service
die(){ echo "PHK1_RECOVERY_ERROR: $*" >&2; exit 78; }
journal_cursor(){ journalctl --user -u "$BRIDGE_UNIT" -n0 --show-cursor 2>/dev/null | sed -n 's/^-- cursor: //p' | tail -1 || true; }
monotonic_ns(){ python3 -c 'import time; print(time.monotonic_ns())'; }
sha(){ sha256sum -- "$1" | awk '{print $1}'; }
usb_path_for(){ local s="$1" f; for f in /sys/bus/usb/devices/*/serial; do [[ -r "$f" ]] || continue; [[ "$(cat "$f")" == "$s" ]] && basename "$(dirname "$f")"; done; }
usb_node_for(){ local d="/sys/bus/usb/devices/$1"; printf '/dev/bus/usb/%03d/%03d' "$(cat "$d/busnum")" "$(cat "$d/devnum")"; }
check_images(){ [[ -r "$XBT" && "$(sha "$XBT")" == "$XBT_SHA" ]] || die 'known-good XBT image hash mismatch'; [[ -r "$PHK" && "$(sha "$PHK")" == "$PHK_SHA" ]] || die 'PHK image hash mismatch'; }
check_ids(){
 [[ "$(usb_path_for "$CANARY_USB")" == 1-9.3 ]] || die 'canary serial/path mismatch'
 [[ "$(usb_path_for "$PEER_USB")" == 1-9.4 ]] || die 'peer serial/path mismatch'
 [[ "$(grep -Rlx -- "$CANARY_USB" /sys/bus/usb/devices/*/serial 2>/dev/null | wc -l)" == 1 ]] || die 'canary serial is not unique'
 [[ "$(grep -Rlx -- "$PEER_USB" /sys/bus/usb/devices/*/serial 2>/dev/null | wc -l)" == 1 ]] || die 'peer serial is not unique'
 local live_log="$HOME/civiclight-testbench/miner/logs/bridge.log"
 [[ -r "$live_log" ]] || die 'current bridge identity log is unavailable'
 grep -q "$CANARY_JTAG" "$live_log" || die 'canary JTAG identity missing from retained bridge log'
 grep -q 'DNA: 4000000001295d813c80a445' "$live_log" || die 'canary DNA missing from retained bridge log'
 grep -q 'DNA: 40000000012922a63c70a3c5' "$live_log" || die 'peer DNA missing from retained bridge log'
 [[ "$(grep -c 'IDCODE(04b69093)' "$live_log")" -ge 2 ]] || die 'both FPGA IDCODEs not present in retained bridge log'
}
bridge_state(){
 local active pid ports_free handles_free canode peernode
 active="$(systemctl --user show -p ActiveState --value "$BRIDGE_UNIT" 2>/dev/null || true)"
 pid="$(systemctl --user show -p MainPID --value "$BRIDGE_UNIT" 2>/dev/null || echo 0)"
 ports_free=1; ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq '(^|:)22110$' && ports_free=0
 ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq '(^|:)22111$' && ports_free=0
 canode="$(usb_node_for 1-9.3)"; peernode="$(usb_node_for 1-9.4)"
 handles_free=1; [[ -n "$(lsof -t "$canode" "$peernode" 2>/dev/null)" ]] && handles_free=0
 if [[ "$active" == active && "$pid" =~ ^[1-9][0-9]*$ && $ports_free -eq 0 ]]; then echo BRIDGE_RUNNING; return 0; fi
 if [[ "$active" =~ ^(inactive|failed)$ && "$pid" == 0 && $ports_free -eq 1 && $handles_free -eq 1 ]]; then echo BRIDGE_STOPPED_EXPECTED; return 0; fi
 if [[ "$active" == failed ]]; then echo BRIDGE_FAILED; return 0; fi
 echo BRIDGE_STOPPING; return 0
}
wait_bridge_released(){
 local deadline=$((SECONDS+45)) state
 while ((SECONDS<deadline)); do
  state="$(bridge_state)"
  [[ "$state" == BRIDGE_STOPPED_EXPECTED ]] && return 0
  [[ "$state" == BRIDGE_FAILED ]] && die 'bridge failed but still owns listeners/USB handles; inspect diagnostics'
  sleep 1
 done
 die 'bounded bridge release timeout'
}
stop_dedicated(){
 for f in "$STATE"/*.pid; do [[ -r "$f" ]] || continue; local p cmd; p="$(cat "$f")"; [[ "$p" =~ ^[0-9]+$ ]] || die 'malformed saved bridge PID'
  kill -0 "$p" 2>/dev/null || continue; cmd="$(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null || true)"
  [[ "$cmd" == *sqrl_bridge_rawjtag_coe* && "$cmd" == *",$CANARY_USB"* ]] || die 'saved PID no longer identifies dedicated target bridge'
  kill -TERM "$p"; for _ in $(seq 1 15); do kill -0 "$p" 2>/dev/null || break; sleep 1; done
  if kill -0 "$p" 2>/dev/null; then kill -KILL "$p"; fi
 done
 local xvc_listeners=1
 for _ in $(seq 1 15); do
  xvc_listeners="$(ss -ltn 2>/dev/null | awk -v p=":$XVCPORT" '$1=="LISTEN" && $4 ~ (p"$") {n++} END {print n+0}')"
  [[ "$xvc_listeners" == 0 ]] && break
  sleep 1
 done
 [[ "$xvc_listeners" == 0 ]] || die 'XVC listener remains after dedicated target shutdown'
}
shared_restore_verified(){
 local pid saved log
 [[ "$(bridge_state)" == BRIDGE_RUNNING && -r "$STATE/SHARED_BRIDGE_RESTORE_VERIFIED" ]] || return 1
 pid="$(systemctl --user show -p MainPID --value "$BRIDGE_UNIT" 2>/dev/null || echo 0)"
 saved="$(cat "$STATE/SHARED_BRIDGE_RESTORE_VERIFIED" 2>/dev/null || true)"
 [[ "$pid" =~ ^[1-9][0-9]*$ && "$saved" == "$pid" ]] || return 1
 log="$STATE/shared-restore.log.window"
 [[ -r "$log" ]] || return 1
 python3 "$ROOT/tools/phk1_raw_bscan/attach_only_recovery_audit.py" --root "$ROOT" --state "$STATE" --log "$log" >/dev/null 2>&1
}
recovery_units_restored(){
 for spec in "$REC_CANARY:canary" "$REC_PEER:peer"; do
  local unit="${spec%%:*}" label="${spec##*:}" prior active
  [[ -r "$STATE/${label}-recovery-active-state" ]] || return 1
  prior="$(cat "$STATE/${label}-recovery-active-state")"; active="$(systemctl is-active "$unit" 2>/dev/null || true)"
  [[ "$(systemctl show -p UnitFileState --value "$unit" 2>/dev/null || true)" != masked ]] || return 1
  if [[ "$prior" == active ]]; then [[ "$active" == active ]] || return 1
  else [[ "$active" != active ]] || return 1; fi
 done
 for unit in "$CANARY_UNIT" "$PEER_UNIT"; do
  [[ "$(systemctl --user show -p UnitFileState --value "$unit" 2>/dev/null || true)" != masked ]] || return 1
 done
 [[ ! -e "$CLAIM_0711" && ! -e "$CLAIM_0957" ]] || return 1
 return 0
}
restore_recovery_unit(){
 local unit="$1" label="$2" prior
 [[ -r "$STATE/${label}-recovery-active-state" ]] || die "missing saved recovery state for $unit"
 prior="$(cat "$STATE/${label}-recovery-active-state")"
 sudo -n systemctl unmask --runtime "$unit"
 if [[ "$prior" == active ]]; then
  sudo -n systemctl reset-failed "$unit" || true
  sudo -n systemctl start "$unit"
  [[ "$(systemctl is-active "$unit")" == active ]] || die "$unit was active before maintenance but did not restore"
 else
  sudo -n systemctl stop "$unit" || true
  sudo -n systemctl reset-failed "$unit" || true
  [[ "$(systemctl is-active "$unit" || true)" != active ]] || die "$unit was inactive before maintenance but became active"
 fi
}
start_rollback(){
  local role_lock="$STATE/PHK1_TARGET_LOCK_VERIFY.json"
  [[ -r "$role_lock" ]] || role_lock="$STATE/PHK1_TARGET_LOCK_PROGRAM.json"
  [[ -r "$role_lock" ]] || die 'recovery has no v2 current/candidate/rollback role lock'
  python3 "$ROOT/tools/phk1_raw_bscan/recovery_v2_roles.py" --lock "$role_lock" --rollback "$XBT" --rollback-binding "$ROLLBACK_BINDING" \
    >"$STATE/recovery-v2-image-role.json" || die 'v2 rollback role validation failed'
  check_ids
  local canode peernode; canode="$(usb_node_for 1-9.3)"; peernode="$(usb_node_for 1-9.4)"
  [[ "$(lsof -t "$canode" "$peernode" 2>/dev/null | wc -l)" == 0 ]] || die 'USB handles are not released before rollback'
  local log="$STATE/emergency-target-rollback.log"
  nohup env LANG=C LC_ALL=C LD_LIBRARY_PATH="$LIBS" "$BRIDGE" -s ",$CANARY_USB" -b "$XBT" -p "$PORT" -t -f "$log" </dev/null >"$log.stdout" 2>&1 &
  local p=$!; echo "$p" >"$STATE/emergency-rollback.pid"
  local deadline=$((SECONDS+180)); while ((SECONDS<deadline)); do kill -0 "$p" 2>/dev/null || die 'target rollback bridge exited'; grep -q 'Bitstream Loaded' "$log" 2>/dev/null && break; sleep 1; done
  grep -q 'Bitstream Loaded' "$log" || die 'target rollback load timed out'
  grep -q "Using Bitstream $XBT for SQRL JTAG Board 0 Device 0" "$log" || die 'target rollback used unexpected image'
  grep -q "$CANARY_JTAG" "$log" || die 'target rollback serial mismatch'
  grep -q 'DNA: 4000000001295d813c80a445' "$log" || die 'target rollback DNA mismatch'
  [[ "$(lsof -t "$canode" 2>/dev/null | grep -cx "$p" || true)" == 1 ]] || die 'rollback did not open exactly target USB path'
  [[ "$(lsof -t "$peernode" 2>/dev/null | wc -l)" == 0 ]] || die 'target rollback opened peer USB handle'
  kill -TERM "$p"; for _ in $(seq 1 15); do kill -0 "$p" 2>/dev/null || break; sleep 1; done
  kill -0 "$p" 2>/dev/null && die 'rollback bridge did not close cleanly'
  wait "$p" 2>/dev/null || true
}
if [[ "$MODE" == --dry-run ]]; then
 check_images; check_ids
 [[ -d "$STATE" ]] || die 'state directory missing'
 [[ -r "$ROOT/PHK1_CANARY_TARGET_BINDING.json" && -r "$ROOT/PROTECTED_WORKLOAD_IDENTITIES.json" ]] || die 'target binding or workload identity manifest missing'
 [[ -r "$ROOT/evidence/live-dryrun-inventory.json" ]] || die 'live dry-run inventory missing'
 [[ -r "$ROOT/tools/phk1_target_dryrun_checks.py" ]] || die 'recovery decision model missing'
 decision_json="$(python3 "$ROOT/tools/phk1_target_dryrun_checks.py" \
  --target "$ROOT/PHK1_CANARY_TARGET_BINDING.json" \
  --inventory "$ROOT/evidence/live-dryrun-inventory.json" \
  --identities "$ROOT/PROTECTED_WORKLOAD_IDENTITIES.json")" || die 'recovery decision simulation failed'
python3 - "$decision_json" <<'PY' || die 'injected emergency recovery decisions failed'
import json,sys
x=json.loads(sys.argv[1])
assert x['TARGET_FAILURE_INJECTION_TESTS']=='13/13'
assert x['TARGET_BRIDGE_RECOVERY_DRYRUN']=='PASS'
assert x['mutations']=={'services':0,'miners':0,'bridge':0,'fpga':0,'jtag':0,'phk1_payload':0}
print('TARGET_EMERGENCY_RECOVERY_DRYRUN=PASS')
print('TARGET_FAILURE_INJECTION_TESTS='+x['TARGET_FAILURE_INJECTION_TESTS'])
print('TARGET_BRIDGE_RECOVERY_DRYRUN='+x['TARGET_BRIDGE_RECOVERY_DRYRUN'])
PY
 echo 'EMERGENCY_RECOVERY_DRYRUN=PASS HARDWARE_ACTIONS=0'; exit 0
fi
[[ "$MODE" == --execute ]] || die 'mode must be --dry-run or --execute'
[[ "$STATE" == "$ROOT/evidence/"* && -d "$STATE" ]] || die 'state path is not inside PHK1 evidence root'
mkdir -p "$STATE"
exec 9>"$STATE/recovery.lock"
flock -n 9 || die 'another recovery action holds the lock'
check_images; check_ids
# Idempotent no-op when the retained transaction already proves every state.
# This branch precedes the one-shot mutation guard and does not restart units.
if shared_restore_verified \
   && [[ -e "$STATE/CANARY_IMAGE_RESTORE_VERIFIED" && -e "$STATE/SHARED_BRIDGE_RESTORE_VERIFIED" ]] \
   && [[ "$(systemctl --user show -p ActiveState --value "$CANARY_UNIT")" == active ]] \
   && [[ "$(systemctl --user show -p ActiveState --value "$PEER_UNIT")" == active ]] \
   && [[ -r "$ROOT/PROTECTED_WORKLOAD_IDENTITIES.json" && -r "$ROOT/tools/protected_workload_check.py" ]] \
   && python3 "$ROOT/tools/protected_workload_check.py" "$ROOT/PROTECTED_WORKLOAD_IDENTITIES.json" >/dev/null \
   && recovery_units_restored \
   && sudo -n systemctl is-active --quiet rabid-xbt-node.service \
   && sudo -n systemctl is-active --quiet rabid-xbt-datum.service; then
 echo "EMERGENCY_RECOVERY=PASS ALREADY_RESTORED=true; no service or FPGA action taken"
 exit 0
fi
[[ ! -e "$STATE/EMERGENCY_RECOVERY_ATTEMPTED" ]] || die 'recovery already attempted; operator review required'
RECOVERY_RUN_ID="$(cat "$STATE/RUN_ID" 2>/dev/null || basename "$STATE")"
RECOVERY_START_MONO_NS="$(monotonic_ns)"
printf '{"event":"RECOVERY_BEGIN","run_id":"%s","transaction_id":"%s","mono_ns":%s,"pid":%s}\n' \
 "$RECOVERY_RUN_ID" "$(basename "$STATE")" "$RECOVERY_START_MONO_NS" "$$" >>"$STATE/observer-events.jsonl"
touch "$STATE/EMERGENCY_RECOVERY_ATTEMPTED"
if [[ -e "$CLAIM_0711" || -e "$CLAIM_0957" ]]; then
 [[ -e "$STATE/SCOPED_CLAIMS_CREATION_INTENT" ]] || die 'claims exist without this transaction ownership marker'
else
 touch "$STATE/SCOPED_CLAIMS_CREATION_INTENT"
fi
[[ -e "$CLAIM_0711" ]] || install -m 600 /dev/null "$CLAIM_0711"
[[ -e "$CLAIM_0957" ]] || install -m 600 /dev/null "$CLAIM_0957"
touch "$STATE/SCOPED_CLAIMS_CREATED"
sudo -n systemctl mask --runtime --now "$REC_CANARY" "$REC_PEER"
systemctl --user mask --runtime --now "$CANARY_UNIT" "$PEER_UNIT"
systemctl --user stop "$CANARY_UNIT" "$PEER_UNIT" || true
sudo -n systemctl stop "$REC_CANARY" "$REC_PEER" || true
stop_dedicated
if [[ "$(bridge_state)" == BRIDGE_RUNNING ]]; then systemctl --user stop "$BRIDGE_UNIT" || true; fi
wait_bridge_released
if [[ ! -e "$STATE/CANARY_IMAGE_RESTORE_VERIFIED" ]]; then
 if [[ -e "$STATE/PHK1_PROGRAM_ATTEMPTED" || -e "$STATE/BASELINE_XBT_PROGRAM_ATTEMPTED" ]]; then
  # Restore only the canary to the approved XBT image. The shared bridge below
  # is attach-only and must not be treated as an image programmer.
  start_rollback
  touch "$STATE/CANARY_TARGET_ROLLBACK_VERIFIED" "$STATE/CANARY_IMAGE_RESTORE_VERIFIED"
 elif [[ ! -e "$STATE/PRE_MAINTENANCE_CANARY_IMAGE_XBT_VERIFIED" ]]; then
  # No image operation was attempted: hardware configuration stayed unchanged.
  touch "$STATE/CANARY_IMAGE_STATE_UNCHANGED_VERIFIED" "$STATE/CANARY_IMAGE_RESTORE_VERIFIED"
 else
  touch "$STATE/CANARY_IMAGE_RESTORE_VERIFIED"
 fi
fi
if ! shared_restore_verified; then
 # The shared launcher loads XBT on both verified cards. Restart it only when
 # the same live bridge instance is not already bound to a verified restore.
 if [[ "$(bridge_state)" == BRIDGE_RUNNING ]]; then systemctl --user stop "$BRIDGE_UNIT" || true; fi
 wait_bridge_released
 systemctl --user mask --runtime "$CANARY_UNIT" "$PEER_UNIT" 2>/dev/null || true
 [[ -e "$STATE/SCOPED_CLAIMS_CREATION_INTENT" ]] || die 'refusing to remove claims not created by this transaction'
 rm -f "$CLAIM_0711" "$CLAIM_0957"
 blog="$HOME/civiclight-testbench/miner/logs/bridge.log"
 python3 "$LOG_AUDIT" snapshot-stat --log "$blog" --output "$STATE/emergency-shared-restore.before.json" >/dev/null
 journal_before="$(journal_cursor)"
 restore_start="$(date -u +%FT%T.%NZ)"
 restore_start_mono_ns="$(monotonic_ns)"
 systemctl --user reset-failed "$BRIDGE_UNIT" 2>/dev/null || true
 systemctl --user start "$BRIDGE_UNIT"
 restore_complete=0
 bridge_pid=""
 bridge_start_ticks=""
 for _ in $(seq 1 240); do
  if [[ "$(bridge_state)" == BRIDGE_RUNNING ]] && ss -ltn 2>/dev/null | grep -q ':22110' && ss -ltn 2>/dev/null | grep -q ':22111'; then
   current_bridge_pid="$(systemctl --user show -p MainPID --value "$BRIDGE_UNIT")"
   [[ "$current_bridge_pid" =~ ^[1-9][0-9]*$ ]] || die 'shared bridge process identity missing during restore window'
   if [[ -z "$bridge_pid" ]]; then
    bridge_pid="$current_bridge_pid"
    bridge_start_ticks="$(awk '{print $22}' "/proc/$bridge_pid/stat")"
   elif [[ "$bridge_pid" != "$current_bridge_pid" ]]; then
    die 'shared bridge process instance changed during restore log window'
   fi
   journal_after="$(journal_cursor)"
   restore_end_mono_ns="$(monotonic_ns)"
   mapfile -t current_sqrl_pids < <(for f in /proc/[0-9]*/cmdline; do
    [[ -r "$f" ]] || continue
    args="$(tr '\0' ' ' <"$f" 2>/dev/null || true)"
    [[ "$args" == *sqrl_bridge_rawjtag_coe* && "$args" == *"$CANARY_USB"* && "$args" == *"$PEER_USB"* ]] && basename "$(dirname "$f")"
   done)
   capture_args=()
   for sqrl_pid in "${current_sqrl_pids[@]}"; do capture_args+=(--sqrl-pid "$sqrl_pid"); done
   python3 "$LOG_AUDIT" capture-window --log "$blog" --before "$STATE/emergency-shared-restore.before.json" \
    --output "$STATE/shared-restore.log.window.pending" --metadata "$STATE/shared-restore.window.pending.json" \
    --transaction-id "$(basename "$STATE")" --run-id "$RECOVERY_RUN_ID" \
    --start-utc "$restore_start" --start-monotonic-ns "$restore_start_mono_ns" \
    --end-monotonic-ns "$restore_end_mono_ns" --process-start-ticks "$bridge_start_ticks" \
    --process-id "$bridge_pid" --bridge-unit "$BRIDGE_UNIT" \
    --journal-cursor-before "$journal_before" --journal-cursor-after "$journal_after" "${capture_args[@]}" >/dev/null
   mv "$STATE/shared-restore.log.window.pending" "$STATE/shared-restore.log.window"
  mv "$STATE/shared-restore.window.pending.json" "$STATE/shared-restore.window.json"
   # Defer the semantic 8/8 audit until the two temporarily stopped workers
   # have been restored below; bridge profile/log identity is checked there.
   restore_complete=1
   break
  fi
  sleep 1
 done
 [[ "$(bridge_state)" == BRIDGE_RUNNING ]] || die 'shared bridge restore failed'
 (( restore_complete == 1 )) || die 'bounded recovery window did not prove attach-only bridge identities/listeners/workload continuity'
fi
restore_recovery_unit "$REC_CANARY" canary
restore_recovery_unit "$REC_PEER" peer
systemctl --user unmask --runtime "$CANARY_UNIT" "$PEER_UNIT"
systemctl --user start "$CANARY_UNIT" "$PEER_UNIT"
for _ in $(seq 1 120); do [[ "$(systemctl --user show -p ActiveState --value "$CANARY_UNIT")" == active && "$(systemctl --user show -p ActiveState --value "$PEER_UNIT")" == active ]] && break; sleep 1; done
[[ "$(systemctl --user show -p ActiveState --value "$CANARY_UNIT")" == active ]] || die 'canary miner restore failed'
[[ "$(systemctl --user show -p ActiveState --value "$PEER_UNIT")" == active ]] || die 'peer miner restore failed'
if [[ -r "$STATE/shared-restore.log.window" ]]; then
 bridge_pid="$(systemctl --user show -p MainPID --value "$BRIDGE_UNIT" 2>/dev/null || echo 0)"
 [[ "$bridge_pid" =~ ^[1-9][0-9]*$ ]] || die 'restored bridge PID missing before final audit'
 python3 "$ROOT/tools/phk1_raw_bscan/attach_only_recovery_audit.py" --root "$ROOT" --state "$STATE" \
  --log "$STATE/shared-restore.log.window" >"$STATE/attach-only-audit.stdout" 2>"$STATE/attach-only-audit.stderr" \
  || die 'attach-only recovery audit failed after workload restoration'
 echo "$bridge_pid" >"$STATE/SHARED_BRIDGE_RESTORE_VERIFIED"
 printf 'ATTACH_ONLY\n' >"$STATE/RESTORE_MODE"
fi
RECOVERY_END_MONO_NS="$(monotonic_ns)"
printf '{"event":"RECOVERY_COMPLETE","run_id":"%s","transaction_id":"%s","mono_ns":%s,"pid":%s}\n' \
 "$RECOVERY_RUN_ID" "$(basename "$STATE")" "$RECOVERY_END_MONO_NS" "$$" >>"$STATE/observer-events.jsonl"
echo "EMERGENCY_RECOVERY=PASS STATE=$STATE"
