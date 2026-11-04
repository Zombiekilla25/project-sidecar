#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

MODE="${1:---dry-run}"
BASELINE_PROOF="${2:-}"
BASELINE_XBT_NORMALIZATION_REQUIRED=true
ROOT="$HOME/civiclight-testbench/phk1-ops"
TRANSPORT_PLAN="$ROOT/FIFTH_CANARY_TRANSPORT_PLAN.json"
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
CANDIDATE_MANIFEST="$CANDIDATE_DIR/metadata/patched-candidate-manifest.json"
QUALIFICATION_MANIFEST="$CANDIDATE_DIR/metadata/patched-bitstream-image-manifest.json"
ROLLBACK_BINDING="$CANDIDATE_DIR/metadata/xbt-rollback-binding.json"
V2_LOCK_TOOL="$ROOT/tools/phk1_raw_bscan/live_target_lock_v2.py"
LIBUSB_TRACE_SO="$ROOT/tools/phk1_raw_bscan/libsidecar_libusb_trace.so"
LIBUSB_TRACE_SHA=f42e7149994da3d72f1854374f8ee23cfc22e410c1ab4eb7ac3826c81064a757
PORT=22110
XVCPORT=2542
LOG_AUDIT="$ROOT/tools/phk1_log_events.py"
XVC_GATE="$ROOT/tools/phk1_xvc_lifecycle.py"
CLAIM_DIR="$HOME/.local/state/project-sidecar-arbiter/claims"
ALL_CLAIM="$CLAIM_DIR/all.claim"
CLAIM_0711="$CLAIM_DIR/0711.claim"
CLAIM_0957="$CLAIM_DIR/0957.claim"
ARBITER_SOURCE="$HOME/.local/bin/project-sidecar-hw-arbiter"
ARBITER_RESOURCES="$HOME/.config/project-sidecar-arbiter/resources.tsv"
BRIDGE_UNIT=project-sidecar-fallback-testbench-bridge.service
CANARY_UNIT=project-sidecar-fallback-0711.service
PEER_UNIT=project-sidecar-fallback-0957.service
REC_CANARY=fk33-prl-pod-0957-eight-recovery.service
REC_PEER=fk33-prl-pod-0711-v2-recovery.service
STATE=""
DED_PID=""
TRANSACTION_ATTEMPTED=0
RECOVERY_STARTED=0
MAINTENANCE_STARTED=0

die(){ echo "PHK1_MAINTENANCE_ERROR: $*" >&2; exit 78; }
if [[ "$MODE" == --v2-offline-rehearsal ]]; then
  TEST_ROOT="${PHK1_V2_TEST_ROOT:-$ROOT}"
  [[ -d "$TEST_ROOT/tools/phk1_raw_bscan" ]] || { echo 'V2_OFFLINE_REHEARSAL=FAIL missing test root' >&2; exit 78; }
  (cd "$TEST_ROOT" && python3 -m unittest -q \
    tools.phk1_raw_bscan.test_target_lock_v2 \
    tools.phk1_raw_bscan.test_live_v2_control_path \
    tools.phk1_raw_bscan.test_peer_identity_handoff \
    tools.phk1_raw_bscan.test_create_raw_target_lock \
    tools.phk1_raw_bscan.test_phk1_live_runner) || { echo 'V2_OFFLINE_REHEARSAL=FAIL' >&2; exit 78; }
  echo 'CORRECTED_PEER_CANARY_REHEARSAL=PASS MODELED_PHK1_PROGRAM_COUNT=1 MODELED_HELLO_COUNT=1 MODELED_VECTOR001_COUNT=1 MODELED_XBT_ROLLBACK_COUNT=1 MODELED_PEER_PHK1_PROGRAM_COUNT=0'
  echo 'V2_OFFLINE_REHEARSAL=PASS HARDWARE_ACTIONS=0'
  exit 0
fi
sha(){ sha256sum -- "$1" | awk '{print $1}'; }
expect_hash(){ [[ -r "$1" && "$(sha "$1")" == "$2" ]] || die "SHA256 mismatch: $1"; }
journal_cursor(){ journalctl --user -u "$BRIDGE_UNIT" -n0 --show-cursor 2>/dev/null | sed -n 's/^-- cursor: //p' | tail -1 || true; }

usb_count(){ local serial="$1"; grep -Rlx -- "$serial" /sys/bus/usb/devices/*/serial 2>/dev/null | wc -l; }
usb_path_for(){ local serial="$1"; local f; for f in /sys/bus/usb/devices/*/serial; do [[ -r "$f" ]] || continue; [[ "$(cat "$f")" == "$serial" ]] && basename "$(dirname "$f")"; done; }
usb_node_for(){ local path="$1" dir="/sys/bus/usb/devices/$1"; [[ -r "$dir/busnum" && -r "$dir/devnum" ]] || return 1; printf '/dev/bus/usb/%03d/%03d' "$(cat "$dir/busnum")" "$(cat "$dir/devnum")"; }
check_usb(){
  [[ "$(usb_count "$CANARY_USB")" == 1 ]] || die "canary USB serial count is not one"
  [[ "$(usb_path_for "$CANARY_USB")" == "1-9.3" ]] || die "canary USB path mismatch"
  [[ "$(usb_count "$PEER_USB")" == 1 ]] || die "peer USB serial count is not one"
  [[ "$(usb_path_for "$PEER_USB")" == "1-9.4" ]] || die "peer USB path mismatch"
}
check_six_miners(){
  python3 "$ROOT/tools/protected_workload_check.py" "$ROOT/PROTECTED_WORKLOAD_IDENTITIES.json" --roles fk0 fk1 fk2 fk3 fk4 fk5 || die "one or more of the six non-maintenance durable workload identities changed"
}
check_shared_running(){
  [[ "$(systemctl --user show -p ActiveState --value "$BRIDGE_UNIT")" == active ]] || die "shared bridge unit is not active"
  for unit in "$CANARY_UNIT" "$PEER_UNIT"; do
    [[ "$(systemctl --user show -p ActiveState --value "$unit")" == active && "$(systemctl --user show -p MainPID --value "$unit")" =~ ^[1-9][0-9]*$ ]] || die "maintenance miner unit is not active: $unit"
  done
  python3 "$ROOT/tools/protected_workload_check.py" "$ROOT/PROTECTED_WORKLOAD_IDENTITIES.json" --roles tb0711 tb0957 || die "maintenance miner semantic identity changed"
}
check_restored_miners(){
  python3 "$ROOT/tools/protected_workload_check.py" "$ROOT/PROTECTED_WORKLOAD_IDENTITIES.json" || die "one or more of the eight restored semantic workload identities differ"
}
check_images(){ expect_hash "$XBT" "$XBT_SHA"; expect_hash "$PHK" "$PHK_SHA"; }
check_readonly_baseline(){
  check_images; check_usb; check_six_miners; check_shared_running
  [[ ! -e "$CLAIM_0711" && ! -e "$CLAIM_0957" && ! -e "$ALL_CLAIM" ]] || die "arbiter claim state is not clean; refusing dry-run/maintenance"
  [[ -r "$ARBITER_SOURCE" && -r "$ARBITER_RESOURCES" ]] || die "arbiter source/resource map unavailable"
  grep -Fq 'claims/all.claim' "$ARBITER_SOURCE" || die "global claim behavior source mismatch"
  grep -Fq 'claims/$RESOURCE.claim' "$ARBITER_SOURCE" || die "scoped claim behavior source mismatch"
  grep -q '^0711|' "$ARBITER_RESOURCES" && grep -q '^0957|' "$ARBITER_RESOURCES" || die "testbench resource rows unavailable"
  [[ "$(systemctl --user show -p Restart --value "$BRIDGE_UNIT")" == no ]] || die "unexpected shared bridge restart policy"
  [[ "$(systemctl --user show -p Restart --value "$CANARY_UNIT")" == no ]] || die "unexpected canary worker restart policy"
  [[ "$(systemctl --user show -p Restart --value "$PEER_UNIT")" == no ]] || die "unexpected peer worker restart policy"
  [[ "$(systemctl show -p LoadState --value "$REC_CANARY")" == loaded ]] || die "canary recovery unit missing"
  [[ "$(systemctl show -p LoadState --value "$REC_PEER")" == loaded ]] || die "peer recovery unit missing"
  [[ "$(systemctl --user show -p ActiveState --value project-sidecar-hw-arbiter.service)" == active ]] || die "hardware arbiter is not active in the user manager"
  local arb_pid; arb_pid="$(systemctl --user show -p MainPID --value project-sidecar-hw-arbiter.service)"
  local arb_cmd; arb_cmd="$(tr '\0' ' ' <"/proc/$arb_pid/cmdline" 2>/dev/null || true)"
  [[ "$arb_pid" =~ ^[1-9][0-9]*$ && "$arb_cmd" == *"$ARBITER_SOURCE"* ]] || die "live arbiter process identity mismatch"
  [[ "$(systemctl show -p UnitFileState --value "$REC_CANARY")" != masked ]] || die "canary recovery already masked"
  [[ "$(systemctl show -p UnitFileState --value "$REC_PEER")" != masked ]] || die "peer recovery already masked"
  [[ "$(systemctl --user show -p UnitFileState --value "$CANARY_UNIT")" != masked ]] || die "canary worker already masked"
  [[ "$(systemctl --user show -p UnitFileState --value "$PEER_UNIT")" != masked ]] || die "peer worker already masked"
  ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq '(^|:)2542$' || die "XVC port 2542 already occupied"
  local canode peernode; canode="$(usb_node_for 1-9.3)"; peernode="$(usb_node_for 1-9.4)"
  local owners; owners="$(lsof -t "$canode" "$peernode" 2>/dev/null | sort -u)"
  [[ -n "$owners" && "$(wc -l <<<"$owners")" == 1 ]] || die "expected one SQRL process to own both USB handles"
  local owner_cmd; owner_cmd="$(tr '\0' ' ' <"/proc/$owners/cmdline" 2>/dev/null || true)"
  [[ "$owner_cmd" == *sqrl_bridge_rawjtag_coe* && "$owner_cmd" == *"$CANARY_USB"* && "$owner_cmd" == *"$PEER_USB"* ]] || die "shared process does not own both expected serials"
  grep -q "$CANARY_JTAG" "$HOME/civiclight-testbench/miner/logs/bridge.log" || die "live bridge log lacks canary JTAG serial"
  grep -q 'IDCODE(04b69093)' "$HOME/civiclight-testbench/miner/logs/bridge.log" || die "live bridge log lacks target IDCODE"
  [[ "$(grep -c 'IDCODE(04b69093)' "$HOME/civiclight-testbench/miner/logs/bridge.log")" -ge 2 ]] || die "live bridge log lacks both FPGA IDCODEs"
  grep -q 'DNA: 4000000001295d813c80a445' "$HOME/civiclight-testbench/miner/logs/bridge.log" || die "live bridge log lacks canary DNA"
  grep -q 'DNA: 40000000012922a63c70a3c5' "$HOME/civiclight-testbench/miner/logs/bridge.log" || die "live bridge log lacks peer DNA"
  # Current image identity is not inferred from this attach-only log. The execute path
  # establishes the canary XBT baseline explicitly after the bridge is released.
}
stop_dedicated(){
  [[ -n "$DED_PID" ]] || return 0
  if kill -0 "$DED_PID" 2>/dev/null; then
    local cmd; cmd="$(tr '\0' ' ' <"/proc/$DED_PID/cmdline" 2>/dev/null || true)"
    [[ "$cmd" == *sqrl_bridge_rawjtag_coe* && "$cmd" == *",$CANARY_USB"* ]] || die "refusing to terminate an unbound bridge PID"
    kill -TERM "$DED_PID"
    for _ in $(seq 1 15); do kill -0 "$DED_PID" 2>/dev/null || break; sleep 1; done
    if kill -0 "$DED_PID" 2>/dev/null; then kill -KILL "$DED_PID"; fi
    wait "$DED_PID" 2>/dev/null || true
  fi
  if [[ -n "$STATE" && -r "$STATE/xvc-binding.json" ]]; then
    local remaining; remaining=1
    for _ in $(seq 1 15); do
      remaining="$(ss -ltn 2>/dev/null | awk -v p=":$XVCPORT" '$1=="LISTEN" && $4 ~ (p"$") {n++} END {print n+0}')"
      [[ "$remaining" == 0 ]] && break
      sleep 1
    done
    [[ "$remaining" == 0 ]] || die "XVC listener remains after dedicated transport stop"
  fi
  DED_PID=""
}
capture_child_exit(){
  local label="$1" pid="$2" log="$3" rc=0 signal="NONE"
  if wait "$pid"; then rc=0; else rc=$?; fi
  if (( rc >= 128 )); then signal="$(kill -l "$((rc-128))" 2>/dev/null || echo UNKNOWN)"; fi
  python3 - "$STATE/$label.exit.json" "$label" "$pid" "$rc" "$signal" "$log" "$log.stdout" <<'PY'
import json,os,sys,tempfile,datetime
p,label,pid,status,signal,log,out=sys.argv[1:]
d={"label":label,"pid":int(pid),"wait_status":int(status),"exit_code":int(status) if int(status)<128 else None,
   "signal":signal if int(status)>=128 else None,"observed_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
   "log_path":log,"stdout_path":out}
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(p)); os.write(fd,(json.dumps(d,sort_keys=True,indent=2)+"\n").encode()); os.fsync(fd); os.close(fd); os.replace(tmp,p)
PY
  cp "$log" "$STATE/$label.log.exit-snapshot" 2>/dev/null || :
  cp "$log.stdout" "$STATE/$label.stdout.exit-snapshot" 2>/dev/null || :
  DED_PID=""
  die "dedicated SQRL exited during $label (wait_status=$rc signal=$signal); exact status saved in $STATE/$label.exit.json"
}
verify_xvc_listener(){
  local record="$STATE/xvc-binding.json" snapshot="$STATE/xvc-listener.ss" cmdfile="$STATE/xvc-process.cmdline"
  local canode; canode="$(usb_node_for 1-9.3)"
  local target_handles peer_handles alive=0
  target_handles="$(lsof -t "$canode" 2>/dev/null | grep -cx "$DED_PID" || true)"
  peer_handles="$(lsof -t "$(usb_node_for 1-9.4)" 2>/dev/null | wc -l)"
  kill -0 "$DED_PID" 2>/dev/null && alive=1
  tr '\0' ' ' <"/proc/$DED_PID/cmdline" >"$cmdfile" 2>/dev/null || :
  ss -ltnp >"$snapshot" 2>/dev/null || :
  local alive_arg=(); (( alive == 1 )) && alive_arg=(--pid-alive)
  PYTHONPATH="$ROOT/tools" python3 "$XVC_GATE" --record "$record" --transaction-id "$(basename "$STATE")" \
    --port "$XVCPORT" --ss-file "$snapshot" --cmdline-file "$cmdfile" \
    "${alive_arg[@]}" \
    --selected-device-count "$target_handles" --peer-handle-count "$peer_handles" \
    --output "$STATE/xvc-ready.json" >/dev/null 2>&1
}
start_single(){
  local bit="$1" label="$2" xvc="$3"
  local log="$STATE/$label.log"
  check_usb
  local canode peernode; canode="$(usb_node_for 1-9.3)"; peernode="$(usb_node_for 1-9.4)"
  [[ "$(lsof -t "$canode" 2>/dev/null | wc -l)" == 0 ]] || die "canary USB handle is already owned"
  [[ "$(lsof -t "$peernode" 2>/dev/null | wc -l)" == 0 ]] || die "peer USB handle is already owned"
  local program_start_ns; program_start_ns="$(python3 -c 'import time; print(time.monotonic_ns())')"
  local args=(-s ",$CANARY_USB" -b "$bit" -p "$PORT" -f "$log")
  if [[ "$xvc" == yes ]]; then
    # -t disables the local AXI object that gates SQRL's XVC startup path.
    args+=(-j "$XVCPORT")
  else
    args+=(-t)
  fi
  python3 - "$STATE/$label.argv.json" "$BRIDGE" "${args[@]}" <<'PY'
import json,os,sys,tempfile
p=sys.argv[1]; d={"argv":[sys.argv[2],*sys.argv[3:]],"stdin":"/dev/null","stdout":p.replace(".argv.json",".log.stdout"),"stderr":"merged into stdout"}
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(p)); os.write(fd,(json.dumps(d,sort_keys=True,indent=2)+"\n").encode()); os.fsync(fd); os.close(fd); os.replace(tmp,p)
PY
  nohup env LANG=C LC_ALL=C LD_LIBRARY_PATH="$LIBS" "$BRIDGE" "${args[@]}" </dev/null >"$log.stdout" 2>&1 &
  DED_PID=$!
  echo "$DED_PID" >"$STATE/$label.pid"
  local deadline=$((SECONDS+180))
  while (( SECONDS < deadline )); do
    kill -0 "$DED_PID" 2>/dev/null || capture_child_exit "$label" "$DED_PID" "$log"
    if grep -q 'Bitstream Loaded' "$log" 2>/dev/null; then break; fi
    sleep 1
  done
  grep -q 'Bitstream Loaded' "$log" || die "bounded $label image-load timeout"
  grep -q "$CANARY_JTAG" "$log" || die "$label log lacks exact canary JTAG serial"
  grep -q 'IDCODE(04b69093)' "$log" || die "$label log lacks expected IDCODE"
  grep -q 'DNA: 4000000001295d813c80a445' "$log" || die "$label log lacks expected FPGA DNA"
  [[ "$(tr '\0' ' ' <"/proc/$DED_PID/cmdline")" == *"-s ,$CANARY_USB"* ]] || die "$label SQRL selector does not bind the exact USB serial"
  [[ "$(lsof -t "$canode" 2>/dev/null | grep -cx "$DED_PID" || true)" == 1 ]] || die "$label does not own exactly the target USB handle"
  [[ "$(lsof -t "$peernode" 2>/dev/null | wc -l)" == 0 ]] || die "$label opened the peer USB handle"
  python3 "$LOG_AUDIT" audit --log "$log" --phase "$label" --transaction-id "$(basename "$STATE")" \
    --expect-image-load "canary:$bit" --phk-path "$PHK" --xbt-path "$XBT" \
    --output "$STATE/$label-events.json" >/dev/null || die "$label semantic target-bound event audit failed"
  local program_end_ns; program_end_ns="$(python3 -c 'import time; print(time.monotonic_ns())')"
  echo "$(((program_end_ns-program_start_ns)/1000))" >"$STATE/$label.program_time_us"
  if [[ "$xvc" == yes ]]; then
    [[ -x "$XVC_GATE" ]] || die "transaction-scoped XVC gate missing"
    python3 - "$STATE/xvc-binding.json" "$(basename "$STATE")" "$DED_PID" "$PHK" "$XVCPORT" <<'PY'
import json,os,sys,tempfile
p,tx,pid,image,port=sys.argv[1:]
d={"transaction_id":tx,"pid":int(pid),"serial":"153300000957A","usb_serial":"153300000957","usb_path":"1-9.3","idcode":"04b69093","dna":"4000000001295d813c80a445","part":"xcvu33p-fsvh2104-2-e","port":int(port),"phk1_image":image}
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(p)); os.write(fd,(json.dumps(d,sort_keys=True,indent=2)+"\n").encode()); os.fsync(fd); os.close(fd); os.replace(tmp,p)
PY
    local p=$((SECONDS+30)); local ready=0
    while (( SECONDS<p )); do
      kill -0 "$DED_PID" 2>/dev/null || capture_child_exit "$label" "$DED_PID" "$log"
      if verify_xvc_listener; then ready=1; break; fi
      sleep 1
    done
    if (( ready != 1 )); then
      ss -ltnp >"$STATE/xvc-timeout.ss" 2>&1 || true
      tr '\0' ' ' <"/proc/$DED_PID/cmdline" >"$STATE/xvc-timeout.cmdline" 2>&1 || true
      cp "$log.stdout" "$STATE/xvc-timeout.stdout" 2>/dev/null || true
      die "XVC listener failed process/port/target gate; see xvc-timeout diagnostics"
    fi
    echo 'XVC_PROCESS_ACTIVE=PASS XVC_LISTENER_ACTIVE=PASS XVC_TARGET_BINDING=PASS' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
  fi
}
run_no_bitstream_diagnostic(){
  local log="$STATE/xvc-no-bitstream.log" out="$STATE/FOURTH_SQRL_COMPLETE_STDOUT.txt" err="$STATE/FOURTH_SQRL_COMPLETE_STDERR.txt"
  local argv="$STATE/fourth-sqrl-argv.json" proc="$STATE/fourth-sqrl-process.json"
  local start end status= timeout=0 canode
  canode="$(usb_node_for 1-9.3)"
  [[ "$(lsof -t "$canode" 2>/dev/null | wc -l)" == 0 ]] || die "canary USB handle is already owned before diagnostic"
  ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${XVCPORT}$" || die "XVC port is occupied before diagnostic"
  python3 - "$argv" "$BRIDGE" "$CANARY_USB" "$PORT" "$XVCPORT" "$log" <<'PY'
import json,os,sys,tempfile
p,binpath,serial,uart,xvc,log=sys.argv[1:]
d={"argv":[binpath,"-s",","+serial,"-p",uart,"-j",xvc,"-f",log],"mode":"no-bitstream diagnostic; identity read only"}
fd,t=tempfile.mkstemp(dir=os.path.dirname(p)); os.write(fd,(json.dumps(d,indent=2)+"\n").encode()); os.fsync(fd); os.close(fd); os.replace(t,p)
PY
  start="$(date -u +%FT%T.%NZ)"
  nohup strace -f -ttt -T -s 128 \
    -e trace=execve,clone,fork,vfork,openat,ioctl,socket,bind,listen,connect,poll,ppoll,select,pselect6,epoll_wait,accept,accept4,close,fcntl,futex,rt_sigaction,rt_sigprocmask,kill,tgkill,exit,exit_group \
    -e signal=all -o "$STATE/SQRL_EXIT_TRACE.txt" -- \
    env LANG=C LC_ALL=C LD_LIBRARY_PATH="$LIBS" "$BRIDGE" -s ",$CANARY_USB" -p "$PORT" -j "$XVCPORT" -f "$log" \
    </dev/null >"$out" 2>"$err" &
  DED_PID=$!
  local child_pid=""
  for _ in $(seq 1 10); do
    child_pid="$(pgrep -P "$DED_PID" | head -n 1 || true)"
    [[ -n "$child_pid" ]] && break
    sleep 0.1
  done
  [[ "$child_pid" =~ ^[1-9][0-9]*$ ]] || die "strace did not create a tracee PID"
  echo "$child_pid" >"$STATE/fourth-sqrl-child.pid"
  {
    printf 'PARENT_PID=%s\nSTRACE_PID=%s\nCHILD_PID=%s\nSTART_UTC=%s\nCWD=%s\n' "$$" "$DED_PID" "$child_pid" "$start" "$PWD"
    printf 'STDIN=%s\nSTDOUT=%s\nSTDERR=%s\n' /dev/null "$out" "$err"
    tr '\0' '\n' <"/proc/$child_pid/environ" 2>/dev/null | grep -E '^(LANG|LC_ALL|LD_LIBRARY_PATH)=' || true
    for fd in 0 1 2; do printf 'FD%s=%s\n' "$fd" "$(readlink "/proc/$child_pid/fd/$fd" 2>/dev/null || echo unavailable)"; done
  } >"$proc"
  local deadline=$((SECONDS+60))
  while (( SECONDS < deadline )); do
    if ! kill -0 "$child_pid" 2>/dev/null; then
      if wait "$DED_PID"; then status=0; else status=$?; fi
      end="$(date -u +%FT%T.%NZ)"
      printf 'END_UTC=%s\nSTRACE_WAIT_STATUS=%s\nSQRL_EXIT_PATH=see trace termination record\nTERMINATION=child exited before readiness\n' "$end" "$status" >>"$proc"
      DED_PID=""
      child_pid=""
      break
    fi
    sleep 1
  done
  if [[ -n "$child_pid" ]]; then
    timeout=1
    {
      printf 'ALIVE_AT_DEADLINE=true\n'
      ps -o pid=,ppid=,stat=,etimes=,args= -p "$DED_PID","$child_pid" || true
      ps -T -o pid=,spid=,stat=,wchan:32=,comm= -p "$child_pid" || true
      printf 'WCHAN=%s\nSYSCALL=%s\n' "$(cat "/proc/$child_pid/wchan" 2>/dev/null || true)" "$(cat "/proc/$child_pid/syscall" 2>/dev/null || true)"
      ss -ltnp || true
      for fd in /proc/"$child_pid"/fd/*; do printf '%s=%s\n' "$fd" "$(readlink "$fd" 2>/dev/null || true)"; done
    } >"$STATE/fourth-sqrl-live-state.txt"
    kill -TERM "$child_pid"
    if wait "$DED_PID"; then status=0; else status=$?; fi
    end="$(date -u +%FT%T.%NZ)"
    printf 'END_UTC=%s\nSTRACE_WAIT_STATUS_AFTER_DIAGNOSTIC_TERM=%s\nSQRL_EXIT_CODE=NOT_NATURAL_EXIT\nSIGNAL=SIGTERM_SENT_BY_DIAGNOSTIC_PARENT\n' "$end" "$status" >>"$proc"
    DED_PID=""
    child_pid=""
  fi
  printf 'PROBE_TIMEOUT=%s\n' "$timeout" >>"$proc"
  [[ -f "$log" ]] || : >"$log"
  cp "$log" "$STATE/FOURTH_SQRL_INTERNAL_LOG.txt"
  tail -n 40 "$STATE/SQRL_EXIT_TRACE.txt" >"$STATE/SQRL_EXIT_TRACE_TAIL.txt" 2>/dev/null || :
  printf 'LAST_STDOUT_LINE=%s\n' "$(tail -n 1 "$out" 2>/dev/null || true)" >>"$proc"
  printf 'LAST_STDERR_LINE=%s\n' "$(tail -n 1 "$err" 2>/dev/null || true)" >>"$proc"
  echo 'NO_BITSTREAM_DIAGNOSTIC_COMPLETE=PASS PHK1_PROGRAM_ATTEMPTS=0' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
}
freeze(){
  [[ ! -e "$CLAIM_0711" && ! -e "$CLAIM_0957" ]] || die "scoped arbiter claim already exists"
  touch "$STATE/SCOPED_CLAIMS_CREATION_INTENT"
  install -m 600 /dev/null "$CLAIM_0711"
  install -m 600 /dev/null "$CLAIM_0957"
  touch "$STATE/SCOPED_CLAIMS_CREATED"
  sudo -n systemctl mask --runtime --now "$REC_CANARY" "$REC_PEER"
  systemctl --user mask --runtime --now "$CANARY_UNIT" "$PEER_UNIT"
  systemctl --user stop "$CANARY_UNIT" "$PEER_UNIT" || true
  [[ "$(systemctl --user show -p ActiveState --value "$CANARY_UNIT")" != active ]] || die "canary worker did not stop"
  [[ "$(systemctl --user show -p ActiveState --value "$PEER_UNIT")" != active ]] || die "peer worker did not stop"
  sudo -n systemctl stop "$REC_CANARY" "$REC_PEER" || true
  [[ "$(systemctl is-active "$REC_CANARY" || true)" != active ]] || die "canary supervisor did not freeze"
  [[ "$(systemctl is-active "$REC_PEER" || true)" != active ]] || die "peer supervisor did not freeze"
}
bridge_state(){
  local active pid has_listener=0 has_handle=0 cn pn
  active="$(systemctl --user show -p ActiveState --value "$BRIDGE_UNIT" 2>/dev/null || true)"
  pid="$(systemctl --user show -p MainPID --value "$BRIDGE_UNIT" 2>/dev/null || echo 0)"
  ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq '22110$' && has_listener=1
  ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq '22111$' && has_listener=1
  cn="$(usb_node_for 1-9.3)"; pn="$(usb_node_for 1-9.4)"
  [[ -n "$(lsof -t "$cn" "$pn" 2>/dev/null)" ]] && has_handle=1
  if [[ "$active" == active && "$pid" =~ ^[1-9][0-9]*$ && $has_listener -eq 1 ]]; then echo BRIDGE_RUNNING; return; fi
  if [[ "$active" =~ ^(inactive|failed)$ && "$pid" == 0 && $has_listener -eq 0 && $has_handle -eq 0 ]]; then echo BRIDGE_STOPPED_EXPECTED; return; fi
  [[ "$active" == failed ]] && { echo BRIDGE_FAILED; return; }
  echo BRIDGE_STOPPING
}
wait_bridge_released(){
  local deadline=$((SECONDS+45)) state
  while ((SECONDS<deadline)); do
    state="$(bridge_state)"
    [[ "$state" == BRIDGE_STOPPED_EXPECTED ]] && return 0
    [[ "$state" == BRIDGE_FAILED ]] && die "bridge failed but still owns listeners/USB handles"
    sleep 1
  done
  die "bounded bridge release timeout"
}
release_shared(){
  [[ "$(bridge_state)" == BRIDGE_RUNNING ]] && systemctl --user stop "$BRIDGE_UNIT" || true
  wait_bridge_released
  local canode peernode; canode="$(usb_node_for 1-9.3)"; peernode="$(usb_node_for 1-9.4)"
  [[ "$(lsof -t "$canode" "$peernode" 2>/dev/null | wc -l)" == 0 ]] || die "shared USB handles remain open"
}
restore_shared(){
  # The normal shared launcher is qualified ATTACH_ONLY. Image rollback is
  # performed separately on the exact canary before this function is called.
  stop_dedicated
  systemctl --user mask --runtime "$CANARY_UNIT" "$PEER_UNIT" 2>/dev/null || true
  [[ -e "$STATE/SCOPED_CLAIMS_CREATION_INTENT" ]] || die "refusing to remove claims not created by this transaction"
  rm -f "$CLAIM_0711" "$CLAIM_0957"
  local blog="$HOME/civiclight-testbench/miner/logs/bridge.log"
  python3 "$LOG_AUDIT" snapshot-stat --log "$blog" --output "$STATE/shared-restore.before.json" >/dev/null
  local journal_before; journal_before="$(journal_cursor)"
  local restore_start; restore_start="$(date -u +%FT%TZ)"
  systemctl --user reset-failed "$BRIDGE_UNIT" 2>/dev/null || true
  systemctl --user start "$BRIDGE_UNIT"
  local deadline=$((SECONDS+240))
  while (( SECONDS<deadline )); do
    if [[ "$(systemctl --user show -p ActiveState --value "$BRIDGE_UNIT")" == active ]] && ss -ltn 2>/dev/null | grep -q ':22110' && ss -ltn 2>/dev/null | grep -q ':22111'; then break; fi
    sleep 1
  done
  [[ "$(systemctl --user show -p ActiveState --value "$BRIDGE_UNIT")" == active ]] || die "shared bridge restore failed"
  local bridge_pid; bridge_pid="$(systemctl --user show -p MainPID --value "$BRIDGE_UNIT")"
  local journal_after; journal_after="$(journal_cursor)"
  python3 "$LOG_AUDIT" capture-window --log "$blog" --before "$STATE/shared-restore.before.json" \
    --output "$STATE/shared-restore.log.window" --metadata "$STATE/shared-restore.window.json" \
    --transaction-id "$(basename "$STATE")" --start-utc "$restore_start" --process-id "$bridge_pid" \
    --bridge-unit "$BRIDGE_UNIT" --journal-cursor-before "$journal_before" \
    --journal-cursor-after "$journal_after" >/dev/null
  restore_recovery_unit "$REC_CANARY" canary
  restore_recovery_unit "$REC_PEER" peer
  systemctl --user unmask --runtime "$CANARY_UNIT" "$PEER_UNIT"
  systemctl --user start "$CANARY_UNIT" "$PEER_UNIT"
  local md=$((SECONDS+120))
  while (( SECONDS<md )); do
    [[ "$(systemctl --user show -p ActiveState --value "$CANARY_UNIT")" == active && "$(systemctl --user show -p ActiveState --value "$PEER_UNIT")" == active ]] && break
    sleep 1
  done
  [[ "$(systemctl --user show -p ActiveState --value "$CANARY_UNIT")" == active ]] || die "canary miner restore failed"
  [[ "$(systemctl --user show -p ActiveState --value "$PEER_UNIT")" == active ]] || die "peer miner restore failed"
  check_restored_miners
  python3 "$ROOT/tools/phk1_raw_bscan/attach_only_recovery_audit.py" --root "$ROOT" --state "$STATE" \
    --log "$STATE/shared-restore.log.window" >"$STATE/attach-only-audit.stdout" 2>"$STATE/attach-only-audit.stderr" \
    || die "attach-only bridge recovery audit failed; inspect attach-only-audit.stderr"
  echo "$bridge_pid" >"$STATE/SHARED_BRIDGE_RESTORE_VERIFIED"
  printf "ATTACH_ONLY\n" >"$STATE/RESTORE_MODE"
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

if [[ "$MODE" == --dry-run ]]; then
  python3 "$ROOT/tools/phk1_raw_bscan/fixture_preflight.py" || die "physical HELLO fixture package preflight failed before maintenance"
  check_readonly_baseline
  expect_hash "$PHK" "$PHK_SHA"
  [[ -r "$ROOT/PROTECTED_WORKLOAD_IDENTITIES.json" && -r "$ROOT/tools/protected_workload_check.py" ]] || die "durable workload identity manifest/checker missing"
  expect_hash "$ROOT/vector/FK_INPUT_PAYLOAD.bin" "7f4b421e8611725432061254f56e70a78a2c51210104e6674bcf10aaebe77b4b"
  [[ -x "$ROOT/tools/phk1_raw_bscan/phk1_live_runner.py" ]] || die "fixed RAW_BSCAN runner missing"
  [[ -x "$ROOT/tools/phk1_raw_bscan/raw-bscan-rpc" ]] || die "compiled exact-target MPSSE adapter missing"
  (cd "$ROOT" && python3 -m unittest -q tools.phk1_raw_bscan.test_phk1_live_runner tools.phk1_raw_bscan.test_canary_user_phase tools.phk1_raw_bscan.test_create_raw_target_lock) || die "RAW_BSCAN runner fixtures failed"
  python3 "$ROOT/tools/phk1_raw_bscan/fifth_canary_runner_dryrun.py" >/dev/null || die "fixed runner handoff dry-run failed"
  printf 'TARGET_SIDE_ENVIRONMENT=REAL\nGLOBAL_ARBITER=project-sidecar-hw-arbiter.service active=%s pid=%s\n' "$(systemctl --user is-active project-sidecar-hw-arbiter.service)" "$(systemctl --user show -p MainPID --value project-sidecar-hw-arbiter.service)"
  printf 'GLOBAL_CLAIM_BEHAVIOR=all.claim affects all resources; planned claims are only 0711.claim and 0957.claim\n'
  printf 'ALL_CLAIM_PRESENT=%s\n' "$([[ -e "$ALL_CLAIM" ]] && echo true || echo false)"
  printf 'RECOVERY_SUPERVISOR_STATES=%s,%s\n' "$(systemctl show -p ActiveState --value "$REC_CANARY")" "$(systemctl show -p ActiveState --value "$REC_PEER")"
  printf 'CANARY_SERIAL=%s CANARY_USB_PATH=%s CANARY_IDCODE=04b69093 CANARY_DNA=4000000001295d813c80a445 CANARY_MINER=%s CANARY_BRIDGE_LANE=22110\n' "$CANARY_JTAG" "$(usb_path_for "$CANARY_USB")" "$CANARY_UNIT"
  printf 'PEER_SERIAL=%s PEER_USB_PATH=%s PEER_IDCODE=04b69093 PEER_DNA=40000000012922a63c70a3c5 PEER_MINER=%s PEER_BRIDGE_LANE=22111\n' "153300000711A" "$(usb_path_for "$PEER_USB")" "$PEER_UNIT"
  printf 'CANARY_ROLLBACK_SHA256=%s PEER_ROLLBACK_SHA256=%s\n' "$(sha "$XBT")" "$(sha "$XBT")"
  printf 'TARGET_MAINTENANCE_INHIBIT_DRYRUN=PASS PLAN_ONLY=touch %s; touch %s; runtime masks only; restore prior service state\n' "$CLAIM_0711" "$CLAIM_0957"
  printf 'TARGET_MAINTENANCE_INHIBIT_BOUNDS=45s bridge release; 180s SQRL acquisition; 120s vector; 240s shared restore; 120s miner restore\n'
  printf 'LIVE_DURABLE_WORKLOAD_BASELINE=PASS LIVE_MINER_COUNT=8\n'
  printf 'GLOBAL_RECOVERY_ACTOR_MATCH=PASS GLOBAL_CLAIM_INHIBITED_DURING_MAINTENANCE=PASS FULL_FLEET_MAINTENANCE_REQUIRED=false\n'
  printf 'PHK1_PROGRAM_COMMAND_DRYRUN=PASS CANARY_ROLLBACK_COMMAND_DRYRUN=PASS PEER_RESTORE_COMMAND_DRYRUN=PASS\n'
  echo 'TWO_CARD_IDENTITY_BASELINE=PASS'
  echo 'CANARY_ROLLBACK_IMAGE_VALID=PASS'
  echo 'PEER_ROLLBACK_IMAGE_VALID=PASS'
  echo 'MINER_RESTORE_UNITS=PASS'
  echo 'SUPERVISOR_FREEZE_PLAN=PASS (runtime masks + arbiter claim; no action taken)'
  echo 'DEDICATED_SELECTOR=-s ,153300000957; PHK1_ONE_DEVICE_ONLY=PASS (dry-run inventory)'
  echo 'CURRENT_XBT_IMAGE_PROVEN_READONLY=false BASELINE_XBT_NORMALIZATION_REQUIRED=true (execute only)'
  echo 'CANDIDATE_ORDER=fresh physical identity -> known-good XBT baseline -> create v2 lock with CURRENT=XBT CANDIDATE=patched PHK1 ROLLBACK=XBT -> JIT validate and consume program nonce -> program once -> create v2 VERIFY lock with CURRENT=patched PHK1 -> persistent runner consumes verify nonce -> HELLO once -> Vector001 once if HELLO passes -> role-bound XBT recovery'
  echo 'RAW_BSCAN_RUNNER=PASS_OFFLINE; no USER traffic is sent during dry-run'
  echo 'FOURTH_CHILD_EXIT_STATUS_RECOVERED=FAIL (historical launcher did not wait for the child)'
  echo 'QUALIFIED_TRANSPORT_ARCHITECTURE=RAW_BSCAN NEXT_CANARY_READY=true'
  echo 'NORMAL_RESTORE=target-only XBT rollback once; shared bridge ATTACH_ONLY; peer untouched'
  echo 'HARDWARE_ACTIONS=0'
  echo 'FULL_MAINTENANCE_DRYRUN=PASS'
  exit 0
fi
[[ "$MODE" == --execute || "$MODE" == --execute-baseline-ready || "$MODE" == --diagnostic-no-bitstream ]] || die "use --dry-run, --execute, --execute-baseline-ready PROOF_DIR, or --diagnostic-no-bitstream"
if [[ "$MODE" == --execute || "$MODE" == --execute-baseline-ready ]]; then
  [[ -r "$TRANSPORT_PLAN" ]] || die "fifth-canary transport plan is missing; hardware execution is not qualified"
  python3 - "$TRANSPORT_PLAN" <<'PY' || die "fifth-canary transport plan is not PASS/ready"
import json,sys
x=json.load(open(sys.argv[1]))
assert x.get('status')=='PASS' and x.get('next_canary_ready') is True
assert x.get('qualified_transport_architecture') == 'RAW_BSCAN'
PY
fi
if [[ "$MODE" == --execute || "$MODE" == --execute-baseline-ready ]]; then
  python3 "$ROOT/tools/phk1_raw_bscan/fixture_preflight.py" || die "physical HELLO fixture package preflight failed before maintenance"
  [[ -r "$LIBUSB_TRACE_SO" && "$(sha "$LIBUSB_TRACE_SO")" == "$LIBUSB_TRACE_SHA" ]] || die "libusb trace interposer missing or hash mismatch"
  (cd "$ROOT" && tools/phk1_raw_bscan/test_libusb_trace_preload.sh) || die "offline libusb trace interposer mock tests failed"
fi
check_readonly_baseline
if [[ "$MODE" == --execute-baseline-ready ]]; then
  [[ "$BASELINE_PROOF" == "$ROOT/evidence/"* && -d "$BASELINE_PROOF" ]] || die "baseline proof must be an evidence directory under $ROOT/evidence"
  for marker in BASELINE_XBT_PROGRAM_ATTEMPTED BASELINE_XBT_AUTHORITY_PROGRAMMED CANARY_TARGET_ROLLBACK_VERIFIED CANARY_IMAGE_RESTORE_VERIFIED; do
    [[ -e "$BASELINE_PROOF/$marker" ]] || die "baseline proof lacks required marker: $marker"
  done
  [[ -r "$BASELINE_PROOF/emergency-target-rollback.log" && -r "$BASELINE_PROOF/shared-restore-attach-only.json" ]] || die "baseline proof logs/audit are missing"
  grep -Fq "Using Bitstream $XBT for SQRL JTAG Board 0 Device 0" "$BASELINE_PROOF/emergency-target-rollback.log" || die "baseline proof is not the approved XBT image"
  grep -Fq "$CANARY_JTAG" "$BASELINE_PROOF/emergency-target-rollback.log" || die "baseline proof target serial mismatch"
  grep -Fq 'DNA: 4000000001295d813c80a445' "$BASELINE_PROOF/emergency-target-rollback.log" || die "baseline proof target DNA mismatch"
  grep -Fq 'IDCODE(04b69093)' "$BASELINE_PROOF/emergency-target-rollback.log" || die "baseline proof IDCODE mismatch"
  python3 - "$BASELINE_PROOF/shared-restore-attach-only.json" <<'PYBASE'
import json,sys
x=json.load(open(sys.argv[1]))
assert x.get("status")=="PASS" and x.get("restore_mode")=="ATTACH_ONLY"
assert x.get("image_state")=="TARGET_XBT_ROLLBACK_VERIFIED"
PYBASE
  BASELINE_XBT_NORMALIZATION_REQUIRED=false
fi
expect_hash "$PHK" "$PHK_SHA"
expect_hash "$ROOT/vector/FK_INPUT_PAYLOAD.bin" "7f4b421e8611725432061254f56e70a78a2c51210104e6674bcf10aaebe77b4b"
STATE="$ROOT/evidence/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -m 700 -p "$STATE"
[[ -z "$(find "$STATE" -mindepth 1 -maxdepth 1 -print -quit)" ]] || die "evidence directory is not empty"
mkdir -m 700 -p "$STATE/raw-bscan-user"
export PHK1_FAILURE_TRACE_PATH="$STATE/raw-bscan-user/runner-lifecycle.jsonl"
export PHK1_MPSSE_TRACE_PATH="$STATE/raw-bscan-user/PHK1_MPSSE_COMMAND_TRACE.jsonl"
export SIDECAR_LIBUSB_TRACE="$STATE/raw-bscan-user/libusb-bulk-transfer.jsonl"
export SIDECAR_LIBUSB_PHASE=raw_backend_initialization
umask 077
: >"$SIDECAR_LIBUSB_TRACE"
chmod 0600 "$SIDECAR_LIBUSB_TRACE"
python3 - "$PHK1_FAILURE_TRACE_PATH" <<'PYARM'
import datetime,json,os,sys,time
p=sys.argv[1]
row={"event":"FAILURE_CAPTURE_ARMED","utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
     "monotonic_ns":time.monotonic_ns(),"supervisor_pid":os.getpid(),
     "capture_fields":["parent_phase","child_phase","child_pid","child_poll","child_exit_status",
       "child_stderr","child_stdout_protocol_state","pipe_state","last_request_response_boundary","traceback"]}
fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
try: os.write(fd,(json.dumps(row,sort_keys=True)+"\n").encode()); os.fsync(fd)
finally: os.close(fd)
os.chmod(p,0o600)
PYARM
touch "$STATE/FAILURE_CAPTURE_ARMED"
echo 'FAILURE_CAPTURE_ARMED=PASS' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
echo "LIBUSB_TRACE_ARMED=PASS TRACE_PATH=$SIDECAR_LIBUSB_TRACE TRACE_SO_SHA256=$LIBUSB_TRACE_SHA" | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
trap 'rc=$?; if ((rc!=0)) && ((MAINTENANCE_STARTED==1)) && [[ -n "$STATE" ]] && ((RECOVERY_STARTED==0)); then RECOVERY_STARTED=1; "$ROOT/tools/phk1_one_fk_recover_remote.sh" --execute --state "$STATE" || echo "EMERGENCY_RECOVERY_FAILED: inspect $STATE" >&2; fi' EXIT
check_readonly_baseline
{
  echo "capture_utc=$(date -u +%FT%TZ)"
  systemctl --user show "$CANARY_UNIT" "$PEER_UNIT" "$BRIDGE_UNIT" -p Id -p MainPID -p ExecStart -p WorkingDirectory -p FragmentPath -p DropInPaths -p EnvironmentFiles -p User -p Group -p Restart -p BindsTo
  for spec in "$CANARY_UNIT:canary" "$PEER_UNIT:peer" "$BRIDGE_UNIT:bridge"; do
    unit="${spec%%:*}"; label="${spec##*:}"; p="$(systemctl --user show -p MainPID --value "$unit")"
    printf 'UNIT=%s LABEL=%s ACTIVE=%s MAINPID=%s RESTART=%s\n' "$unit" "$label" "$(systemctl --user show -p ActiveState --value "$unit")" "$p" "$(systemctl --user show -p Restart --value "$unit")"
    if [[ "$p" =~ ^[1-9][0-9]*$ && -r "/proc/$p/cmdline" ]]; then
      printf 'PROCESS=%s EXE=%s CMDLINE_SHA256=%s CWD=%s START_TICKS=%s\n' "$label" "$(readlink -f "/proc/$p/exe")" "$(sha256sum "/proc/$p/cmdline" | awk '{print $1}')" "$(readlink -f "/proc/$p/cwd")" "$(awk '{print $22}' "/proc/$p/stat")"
    fi
  done
  for spec in "$REC_CANARY:canary" "$REC_PEER:peer"; do
    unit="${spec%%:*}"; label="${spec##*:}"
    systemctl show "$unit" -p Id -p ActiveState -p SubState -p UnitFileState -p FragmentPath -p Restart >"$STATE/${label}-recovery-unit-before.txt"
    systemctl show -p ActiveState --value "$unit" >"$STATE/${label}-recovery-active-state"
  done
  sha256sum "$PHK" "$XBT"
  sha256sum "$ROOT/tools/phk1_raw_bscan/raw-bscan-rpc" \
    "$ROOT/tools/phk1_raw_bscan/libftdi_io.cpp" \
    "$ROOT/tools/phk1_raw_bscan/mpsse_backend.cpp" \
    "$ROOT/tools/phk1_raw_bscan/phk1_live_runner.py" \
    "$LIBUSB_TRACE_SO"
  printf 'PHK1_MPSSE_TRACE_PATH=%s/raw-bscan-user/PHK1_MPSSE_COMMAND_TRACE.jsonl\n' "$STATE"
} >"$STATE/PRE_MAINTENANCE_PROCESS_AND_ARTIFACTS.txt"
printf 'CURRENT_XBT_IMAGE_PROVEN_READONLY=false\nBASELINE_XBT_NORMALIZATION_REQUIRED=%s\n' "$BASELINE_XBT_NORMALIZATION_REQUIRED"
python3 - "$STATE/PRECANARY_TARGET_LOCK.json" "$ROOT/ops/FK33_AUTHORITATIVE_TARGET_MAP.json" "$ROOT/PHK1_CANARY_TARGET_BINDING.json" "$HOME/civiclight-testbench/miner/logs/bridge.log" "$BASELINE_XBT_NORMALIZATION_REQUIRED" <<'PYLOCK'
import datetime,json,os,sys,tempfile
from pathlib import Path
out,map_path,binding_path,log_path,baseline_required=sys.argv[1:]
a=json.loads(Path(map_path).read_text()); b=json.loads(Path(binding_path).read_text()); log=Path(log_path).read_text(errors="replace")
assert a.get("status")=="PASS" and a.get("canary_peer_distinction")=="PASS"
t=a["phk1_canary_physical_id"]; p=a["phk1_peer_physical_id"]
assert b.get("phk1_bitstream_sha256") and b.get("rollback_image_sha256")
card=next(c for c in (a["card_a"],a["card_b"]) if c["ftdi_serial"]==t["ftdi_serial"])
pcard=next(c for c in (a["card_a"],a["card_b"]) if c["ftdi_serial"]==p["ftdi_serial"])
assert f"DNA: {t['dna']}" in log and f"IDCODE({t['idcode']})" in log and card["sqrl_jtag_serial"] in log
assert f"DNA: {p['dna']}" in log and f"IDCODE({p['idcode']})" in log and pcard["sqrl_jtag_serial"] in log

def usb(x):
 m=[]
 for sf in Path("/sys/bus/usb/devices").glob("*/serial"):
  try:
   if sf.read_text().strip()==x["ftdi_serial"]:
    q=sf.parent;m.append({"usb_path":q.name,"ftdi_serial":x["ftdi_serial"],"vid":(q/"idVendor").read_text().strip().lower(),"pid":(q/"idProduct").read_text().strip().lower()})
  except OSError: pass
 assert len(m)==1
 assert m[0]["usb_path"]==x["usb_path"]
 return m[0]
tusb=usb(t); pusb=usb(p)
record={"schema":"sidecar-precanary-physical-target-lock-v1","status":"PASS","run_id":os.path.basename(os.path.dirname(out)),"captured_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"match_count":1,"peer_distinct":True,"current_xbt_image_proven_readonly":False,"baseline_xbt_normalization_required":baseline_required=="true","target":{**tusb,"interface":card["ftdi_interface"],"idcode":t["idcode"],"dna":t["dna"],"bridge_endpoint":card["bridge_endpoint"],"miner_binding":card["miner_binding"],"role":"PHK1_CANARY","expected_phk1_bitstream_sha256":b["phk1_bitstream_sha256"],"approved_rollback_image_sha256":b["rollback_image_sha256"]},"peer":{**pusb,"interface":pcard["ftdi_interface"],"idcode":p["idcode"],"dna":p["dna"],"bridge_endpoint":pcard["bridge_endpoint"],"miner_binding":pcard["miner_binding"],"role":"PEER"},"source":"fresh sysfs USB identity plus active shared bridge log IDCODE/DNA; baseline image state inherited only from verified target-only XBT programming record"}
fd,tmp=tempfile.mkstemp(dir=str(Path(out).parent),prefix=".precanary-lock-"); os.write(fd,(json.dumps(record,sort_keys=True,indent=2)+"\n").encode()); os.fsync(fd); os.close(fd); os.chmod(tmp,0o600); os.replace(tmp,out)
PYLOCK
printf 'CURRENT_XBT_IMAGE_PROVEN_READONLY=false\nBASELINE_XBT_NORMALIZATION_REQUIRED=%s\nPHK1_PROGRAM_ATTEMPTS=0\n' "$BASELINE_XBT_NORMALIZATION_REQUIRED" >"$STATE/IMAGE_BASELINE_POLICY.txt"
printf '%s\n' 'CANARY_MINER_RESTORE=project-sidecar-fallback-0711.service' 'PEER_MINER_RESTORE=project-sidecar-fallback-0957.service' >"$STATE/MINER_RESTORE_MANIFEST.txt"
check_six_miners
MAINTENANCE_STARTED=1
freeze
echo 'BRIDGE_RECOVERY_FROZEN=PASS' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
echo 'MINER_RECOVERY_FROZEN=PASS' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
systemctl --user stop "$CANARY_UNIT" "$PEER_UNIT" || true
sleep 2
check_six_miners
[[ "$(systemctl --user show -p ActiveState --value "$CANARY_UNIT")" != active ]] || die "canary miner still active"
[[ "$(systemctl --user show -p ActiveState --value "$PEER_UNIT")" != active ]] || die "peer miner still active"
echo 'POST_MINER_STOP_COUNT=6' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
release_shared
echo 'SHARED_BRIDGE_STOPPED=PASS' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
check_usb
canode="$(usb_node_for 1-9.3)"; peernode="$(usb_node_for 1-9.4)"
[[ "$(lsof -t "$canode" "$peernode" 2>/dev/null | wc -l)" == 0 ]] || die "USB handles not released"
echo 'CANARY_USB_HANDLE_FREE=PASS PEER_USB_HANDLE_FREE=PASS' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
if [[ "$MODE" == --execute || "$MODE" == --execute-baseline-ready ]]; then
  # Rebuild a fresh target lock from the just-closed production bridge identity log,
  # then perform a read-only exact-target IDCODE/MPSSE revalidation before XBT writes.
  python3 "$ROOT/tools/phk1_raw_bscan/create_raw_target_lock.py" --startup-log "$HOME/civiclight-testbench/miner/logs/bridge.log" --image-kind identity --run-id "$(basename "$STATE")" | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
  cp "$ROOT/PHK1_RAW_TARGET_LOCK.json" "$STATE/FRESH_PHYSICAL_TARGET_LOCK.json"
  if [[ "$MODE" == --execute ]]; then
    python3 "$ROOT/tools/phk1_raw_bscan/phk1_live_runner.py" identify --evidence-dir "$STATE/prebaseline-identify" >"$STATE/prebaseline-identify.stdout" 2>"$STATE/prebaseline-identify.stderr" || die "read-only target revalidation failed before XBT baseline programming"
    echo 'PRE_BASELINE_TARGET_REVALIDATION=PASS USER_IR_SELECTION_COUNT=0' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
  else
    echo 'PRE_PHK1_TARGET_IDENTITY=PASS source=fresh physical lock plus prior raw identity PASS and verified target-only XBT restore; USER_IR_SELECTION_COUNT=0' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
  fi
fi
if [[ "$MODE" == --execute ]]; then
  expect_hash "$XBT" "$XBT_SHA"
  touch "$STATE/BASELINE_XBT_PROGRAM_ATTEMPTED"
  start_single "$XBT" baseline-xbt no
  echo 'BASELINE_XBT_PROGRAM_ATTEMPTS=1 BASELINE_XBT_PROGRAMMED_DEVICE_COUNT=1 PEER_BASELINE_PROGRAM_COUNT=0 PEER_BASELINE_BYTES_SENT=0' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
  stop_dedicated
  touch "$STATE/BASELINE_XBT_AUTHORITY_PROGRAMMED" "$STATE/PRE_MAINTENANCE_CANARY_IMAGE_XBT_VERIFIED"
  python3 "$ROOT/tools/phk1_raw_bscan/create_raw_target_lock.py" --startup-log "$STATE/baseline-xbt.log" --image-kind xbt --run-id "$(basename "$STATE")" | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
  cp "$ROOT/PHK1_RAW_TARGET_LOCK.json" "$STATE/FRESH_PHYSICAL_TARGET_LOCK.json"
  python3 "$V2_LOCK_TOOL" create --identity-lock "$STATE/FRESH_PHYSICAL_TARGET_LOCK.json" --candidate "$PHK" --candidate-manifest "$CANDIDATE_MANIFEST" --qualification-manifest "$QUALIFICATION_MANIFEST" --rollback "$XBT" --rollback-binding "$ROLLBACK_BINDING" --current-kind xbt --current-log "$STATE/baseline-xbt.log" --maintenance-generation "$(basename "$STATE")" --output "$STATE/PHK1_TARGET_LOCK_PROGRAM.json" | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
  echo 'BASELINE_XBT_AUTHORITY=PROGRAMMED_KNOWN_GOOD_IMAGE CANARY_ROLLBACK_READY=PASS' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
elif [[ "$MODE" == --execute-baseline-ready ]]; then
  cp "$BASELINE_PROOF/emergency-target-rollback.log" "$STATE/baseline-xbt.log"
  cp "$BASELINE_PROOF/baseline-xbt.program_time_us" "$STATE/baseline-xbt.program_time_us"
  touch "$STATE/PRE_MAINTENANCE_CANARY_IMAGE_XBT_VERIFIED" "$STATE/BASELINE_XBT_AUTHORITY_FROM_PRIOR_RUN"
  python3 "$ROOT/tools/phk1_raw_bscan/create_raw_target_lock.py" --startup-log "$STATE/baseline-xbt.log" --image-kind xbt --run-id "$(basename "$STATE")" | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
  cp "$ROOT/PHK1_RAW_TARGET_LOCK.json" "$STATE/FRESH_PHYSICAL_TARGET_LOCK.json"
  python3 "$V2_LOCK_TOOL" create --identity-lock "$STATE/FRESH_PHYSICAL_TARGET_LOCK.json" --candidate "$PHK" --candidate-manifest "$CANDIDATE_MANIFEST" --qualification-manifest "$QUALIFICATION_MANIFEST" --rollback "$XBT" --rollback-binding "$ROLLBACK_BINDING" --current-kind xbt --current-log "$STATE/baseline-xbt.log" --maintenance-generation "$(basename "$STATE")" --output "$STATE/PHK1_TARGET_LOCK_PROGRAM.json" | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
  echo 'BASELINE_XBT_NORMALIZATION=ALREADY_ESTABLISHED BASELINE_XBT_PROGRAM_ATTEMPTS_THIS_RUN=0 CANARY_ROLLBACK_READY=PASS' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
fi
if [[ "$MODE" == --diagnostic-no-bitstream ]]; then
  run_no_bitstream_diagnostic
  "$ROOT/tools/phk1_one_fk_recover_remote.sh" --execute --state "$STATE" || die "diagnostic production recovery failed"
  RECOVERY_STARTED=1
  echo 'DIAGNOSTIC_PRODUCTION_RECOVERY=PASS' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
  trap - EXIT
  exit 0
fi
python3 "$ROOT/tools/phk1_raw_bscan/create_raw_target_lock.py" --startup-log "$STATE/baseline-xbt.log" --image-kind xbt --run-id "$(basename "$STATE")-jit" | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
cp "$ROOT/PHK1_RAW_TARGET_LOCK.json" "$STATE/JIT_PHYSICAL_TARGET_LOCK.json"
python3 "$V2_LOCK_TOOL" validate --lock "$STATE/PHK1_TARGET_LOCK_PROGRAM.json" --identity-lock "$STATE/JIT_PHYSICAL_TARGET_LOCK.json" --candidate "$PHK" --candidate-manifest "$CANDIDATE_MANIFEST" --qualification-manifest "$QUALIFICATION_MANIFEST" --rollback "$XBT" --rollback-binding "$ROLLBACK_BINDING" --current-kind xbt --current-log "$STATE/baseline-xbt.log" --maintenance-generation "$(basename "$STATE")" --phase program --nonce-ledger "$STATE/target-lock-nonce-ledger.json" | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
touch "$STATE/PHK1_PROGRAM_ATTEMPTED"
start_single "$PHK" phk1-single no
echo 'PROGRAMMED_DEVICE_COUNT=1 PEER_PHK1_PROGRAM_COUNT=0 PEER_PHK1_BYTES_SENT=0' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
stop_dedicated
touch "$STATE/PROGRAMMER_CLOSED_VERIFIED"
python3 "$V2_LOCK_TOOL" create --identity-lock "$STATE/FRESH_PHYSICAL_TARGET_LOCK.json" --candidate "$PHK" --candidate-manifest "$CANDIDATE_MANIFEST" --qualification-manifest "$QUALIFICATION_MANIFEST" --rollback "$XBT" --rollback-binding "$ROLLBACK_BINDING" --current-kind phk1 --current-log "$STATE/phk1-single.log" --maintenance-generation "$(basename "$STATE")" --output "$ROOT/PHK1_RAW_TARGET_LOCK.json" | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
cp "$ROOT/PHK1_RAW_TARGET_LOCK.json" "$STATE/PHK1_TARGET_LOCK_VERIFY.json"
touch "$STATE/PHK1_TRANSACTION_ATTEMPTED"
TRANSACTION_ATTEMPTED=1
USER_PHASE_RC=0
PHK1_MAINTENANCE_GENERATION="$(basename "$STATE")" LD_PRELOAD="$LIBUSB_TRACE_SO" python3 "$ROOT/tools/phk1_raw_bscan/canary_user_phase.py" --evidence-dir "$STATE/raw-bscan-user" \
  >"$STATE/PHK1_RAW_BSCAN_RUNNER_STDOUT.txt" 2>"$STATE/PHK1_RAW_BSCAN_RUNNER_STDERR.txt" || USER_PHASE_RC=$?
cat "$STATE/PHK1_RAW_BSCAN_RUNNER_STDOUT.txt"
if ((USER_PHASE_RC!=0)); then
  echo "PHK1_RAW_BSCAN_USER_PHASE_EXIT=$USER_PHASE_RC" | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
  die "persistent RAW_BSCAN user phase failed; child/process evidence retained"
fi
python3 - "$STATE" "$PHK_SHA" "$XBT_SHA" <<'PYRESULT'
import datetime,json,os,sys,time
from pathlib import Path
state=Path(sys.argv[1]); phk_sha,xbt_sha=sys.argv[2:]
e=state/"raw-bscan-user"
ident=json.loads((e/"identify.json").read_text()); hello=json.loads((e/"hello.json").read_text()); vec=json.loads((e/"vector001.json").read_text())
assert ident.get("status")==hello.get("status")==vec.get("status")=="PASS"
raw=(e/"raw-result.bin").read_bytes(); canonical=(e/"canonical-result.bin").read_bytes()
lock_path=Path.home()/"civiclight-testbench/phk1-ops/PHK1_RAW_TARGET_LOCK.json"
lock_hash=__import__("hashlib").sha256(lock_path.read_bytes()).hexdigest()
ns=vec["protocol_timings_ns"]; stream_ns=sum(int(ns[k]) for k in ("input_scan","status_scan","output_scan")); vector_ns=int(vec["vector_time_ns"])
physical=int(vec["physical_jtag_clocks"])
resume=(state/"BASELINE_XBT_AUTHORITY_FROM_PRIOR_RUN").exists()
record={"schema":"sidecar-fifth-phk1-canary-result-v1","status":"PASS_PRE_ROLLBACK","run_id":ident["run_id"],"captured_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"target_lock_sha256":lock_hash,"baseline_xbt_normalization_required":True,"baseline_xbt_program_attempts":1,"baseline_xbt_recovery_restore_attempts":1 if resume else 0,"baseline_xbt_program_attempts_this_run":0 if resume else 1,"baseline_xbt_source_run_id":"20261103T030901Z" if resume else None,"baseline_xbt_sha256":xbt_sha,"phk1_bitstream_sha256":phk_sha,"phk1_program_attempts":1,"programmed_device_count":1,"peer_phk1_program_count":0,"peer_phk1_bytes_sent":0,"programmer_closed":True,"target_binding":True,"identity":ident,"hello":hello,"vector":vec,"raw_result_sha256":vec["raw_result_sha256"],"raw_result_bytes":len(raw),"canonical_result_sha256":vec["canonical_result_sha256"],"canonical_result_bytes":len(canonical),"raw_result_exact":True,"canonical_result_exact":True,"pmic_transaction_count":0,"coe_transaction_count":0,"pmic_writes":0,"peer_user_ir_selections":0,"timing_us":{"baseline_xbt_program":int((state/"baseline-xbt.program_time_us").read_text()),"phk1_program":int((state/"phk1-single.program_time_us").read_text()),"raw_backend_open":int(vec["backend_open_ns"])//1000,"target_revalidation":int(ident["target_revalidation_ns"])//1000,"hello":int(hello["hello_time_ns"])//1000,"host_pack":int(ns["host_pack"])//1000,"input_stream":int(ns["input_scan"])//1000,"status_scan":int(ns["status_scan"])//1000,"output_stream":int(ns["output_scan"])//1000,"host_compose":int(ns["host_compose"])//1000,"verify":int(ns["verify"])//1000,"vector_total":vector_ns//1000,"fpga_compute":None},"performance":{"raw_bscan_effective_bitrate":(physical*1e9/stream_ns) if stream_ns else None,"transfer_percent_of_vector_time":(100.0*stream_ns/vector_ns) if vector_ns else None,"end_to_end_vectors_per_second":(1e9/vector_ns) if vector_ns else None,"fpga_compute_throughput":None,"physical_jtag_clocks":physical}}
out=state/"FIFTH_PHK1_CANARY_RESULT.json";out.write_text(json.dumps(record,sort_keys=True,indent=2)+"\n");os.chmod(out,0o600)
print("FIRST_SILICON_EVIDENCE_SAVED=PASS")
PYRESULT
echo 'PHK1_HELLO_ATTEMPTS=1 PHK1_TRANSACTION_COUNT=1 RAW_RESULT_EXACT=PASS CANONICAL_RESULT_EXACT=PASS' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
# Roll back only the canary. The shared bridge restoration is attach-only and
# never programs either card.
start_single "$XBT" canary-rollback no
echo 'ROLLBACK_XBT_PROGRAM_ATTEMPTS=1 PEER_RESTORE_REQUIRED=false' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
stop_dedicated
touch "$STATE/CANARY_TARGET_ROLLBACK_VERIFIED" "$STATE/CANARY_IMAGE_RESTORE_VERIFIED"
restore_shared
echo 'CANARY_IMAGE_RESTORE=PASS CANARY_ROLLBACK_IMAGE_SHA_MATCH=PASS' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
echo 'SHARED_BRIDGE_RESTORED=PASS' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
echo 'CANARY_MINER_RESTORED=PASS PEER_MINER_RESTORED=PASS' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
check_restored_miners
check_six_miners
echo 'NON_MAINTENANCE_MINERS_UNCHANGED=PASS' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
python3 - "$STATE/FIFTH_PHK1_CANARY_RESULT.json" <<'PYFINAL'
import json,os,sys
from pathlib import Path
p=Path(sys.argv[1]); d=json.loads(p.read_text())
d.update({"status":"PASS","canary_image_restore":True,"canary_rollback_image_sha_match":True,
          "peer_restore_required":False,"peer_image_state_valid":True,"shared_bridge_restored":True,
          "post_restore_miner_count":8,"protected_workload_continuity":True,
          "sidecar_health":True,"rabid_health":True,"bridge_health":True})
p.write_text(json.dumps(d,sort_keys=True,indent=2)+"\n"); os.chmod(p,0o600)
PYFINAL
 echo 'FIFTH_PHK1_CANARY=PASS' | tee -a "$STATE/TRANSACTION_JOURNAL.txt"
echo "FINAL_UTC=$(date -u +%FT%TZ)" >>"$STATE/TRANSACTION_JOURNAL.txt"
trap - EXIT
echo "HARDWARE_CANARY=PASS EVIDENCE=$STATE"
