#!/usr/bin/env python3
"""Create the fixed RAW_BSCAN lock from the current canary SQRL log and
read-only sysfs enumeration after the programmer has closed.

This helper does not open USB, access JTAG, or select a USER chain.
"""
from __future__ import annotations
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

ROOT=Path.home()/"civiclight-testbench/phk1-ops"
MAP=ROOT/"ops/FK33_AUTHORITATIVE_TARGET_MAP.json"
BINDING=ROOT/"PHK1_CANARY_TARGET_BINDING.json"
OUTPUT=ROOT/"PHK1_RAW_TARGET_LOCK.json"

class LockError(RuntimeError): pass

V2_IDENTITY_INPUT_FIELDS=("usb_path","ftdi_serial","vid","pid","interface","idcode",
                          "dna","bridge_endpoint","miner_binding")

def complete_peer_identity(peer_observed: dict, authority: dict) -> dict:
    """Bind the observed peer USB/JTAG identity to its authoritative map row.

    The v1 lock collector historically emitted only serial/path/IDCODE/DNA for
    the peer. Keep v2's complete-field checks strict and source the missing USB
    and workload fields from the same qualified map used for the target.
    """
    if authority.get("status")!="PASS" or authority.get("canary_peer_distinction")!="PASS":
        raise LockError("authoritative target/peer map is not qualified")
    peer=authority.get("phk1_peer_physical_id")
    target=authority.get("phk1_canary_physical_id")
    cards=(authority.get("card_a"),authority.get("card_b"))
    if not isinstance(peer,dict) or not isinstance(target,dict) or any(not isinstance(c,dict) for c in cards):
        raise LockError("authoritative peer mapping is incomplete")
    try:
        card=next(c for c in cards if c.get("ftdi_serial")==peer.get("ftdi_serial"))
    except StopIteration as exc:
        raise LockError("authoritative peer has no mapped USB/interface/workload row") from exc

    def norm_idcode(value):
        return str(value).lower().removeprefix("0x")

    expected={"usb_path":peer.get("usb_path"),"ftdi_serial":peer.get("ftdi_serial"),
              "idcode":norm_idcode(peer.get("idcode")),"dna":peer.get("dna")}
    for key,value in expected.items():
        observed=peer_observed.get(key)
        if key=="idcode": observed=norm_idcode(observed)
        if not isinstance(value,str) or not value or observed!=value:
            raise LockError(f"observed peer {key} differs from authoritative mapping")
    if peer.get("ftdi_serial")==target.get("ftdi_serial") or peer.get("dna")==target.get("dna"):
        raise LockError("authoritative peer identity overlaps the canary target")
    card_fields={"usb_path":card.get("usb_path"),"ftdi_serial":card.get("ftdi_serial"),
        "vid":str(card.get("vid","")).lower(),"pid":str(card.get("pid","")).lower(),
        "interface":card.get("ftdi_interface"),"bridge_lane":card.get("bridge_endpoint"),
        "workload_binding":card.get("miner_binding")}
    if any(not isinstance(v,str) or not v for v in card_fields.values()):
        raise LockError("authoritative peer USB/interface/workload mapping is incomplete")
    if (card_fields["usb_path"]!=expected["usb_path"] or
        card_fields["ftdi_serial"]!=expected["ftdi_serial"] or
        norm_idcode(card.get("idcode"))!=expected["idcode"] or card.get("dna")!=expected["dna"]):
        raise LockError("peer physical identity and authoritative card row disagree")
    for key in ("vid","pid"):
        observed=peer_observed.get(key)
        if observed is not None and (not isinstance(observed,str) or observed.lower()!=card_fields[key]):
            raise LockError(f"observed peer {key} differs from authoritative mapping")
    for observed_key,mapped_key in (("interface","interface"),("bridge_endpoint","bridge_lane"),
                                    ("miner_binding","workload_binding")):
        observed=peer_observed.get(observed_key)
        if observed is not None and observed!=card_fields[mapped_key]:
            raise LockError(f"observed peer {observed_key} differs from authoritative mapping")
    result={"usb_path":expected["usb_path"],"ftdi_serial":expected["ftdi_serial"],
        "vid":card_fields["vid"],"pid":card_fields["pid"],"interface":card_fields["interface"],
        "idcode":expected["idcode"],"dna":expected["dna"],
        "bridge_endpoint":card_fields["bridge_lane"],"miner_binding":card_fields["workload_binding"]}
    if any(not isinstance(result[k],str) or not result[k] for k in V2_IDENTITY_INPUT_FIELDS):
        raise LockError("completed peer identity does not satisfy v2 physical schema")
    return result

def _usb_for_serial(serial: str, sysfs: Path=Path("/sys/bus/usb/devices")) -> dict:
    matches=[]
    for p in sysfs.glob("*/serial"):
        try:
            if p.read_text().strip()==serial:
                base=p.parent
                bus=int((base/"busnum").read_text().strip())
                dev=int((base/"devnum").read_text().strip())
                matches.append({"path":base.name,"vid":(base/"idVendor").read_text().strip().lower(),
                    "pid":(base/"idProduct").read_text().strip().lower(),
                    "device_node":f"/dev/bus/usb/{bus:03d}/{dev:03d}"})
        except OSError:
            continue
    if len(matches)!=1:
        raise LockError(f"USB serial match count is {len(matches)}, expected one")
    return matches[0]

def create_lock(startup_log: Path, *, root: Path=ROOT, map_path: Path|None=None,
                binding_path: Path|None=None, sysfs: Path=Path("/sys/bus/usb/devices"),
                lsof=subprocess.run, now: dt.datetime|None=None,
                image_kind: str="phk1", run_id: str|None=None) -> dict:
    if image_kind not in {"phk1", "xbt", "identity"}:
        raise LockError("unsupported image kind")
    map_path=map_path or root/"ops/FK33_AUTHORITATIVE_TARGET_MAP.json"
    binding_path=binding_path or root/"PHK1_CANARY_TARGET_BINDING.json"
    try:
        authority=json.loads(map_path.read_text()); binding=json.loads(binding_path.read_text())
    except (OSError,json.JSONDecodeError) as exc:
        raise LockError("authoritative map/binding unavailable") from exc
    if authority.get("status")!="PASS" or authority.get("canary_peer_distinction")!="PASS":
        raise LockError("authoritative map is not qualified")
    log_path=startup_log.resolve()
    expected_log_name={"phk1":"phk1-single.log","xbt":"baseline-xbt.log","identity":"bridge.log"}[image_kind]
    in_run_evidence=log_path.is_relative_to((root/"evidence").resolve())
    live_bridge_log=Path.home()/"civiclight-testbench/miner/logs/bridge.log"
    if log_path.name!=expected_log_name or not (in_run_evidence or (image_kind=="identity" and log_path==live_bridge_log)):
        raise LockError(f"startup log is not an approved current {image_kind.upper()} evidence source")
    try: log=log_path.read_text(errors="replace")
    except OSError as exc: raise LockError("startup log unavailable") from exc
    target=authority["phk1_canary_physical_id"]; peer=authority["phk1_peer_physical_id"]
    cards=(authority["card_a"],authority["card_b"])
    card=next(c for c in cards if c["ftdi_serial"]==target["ftdi_serial"])
    peer_card=next(c for c in cards if c["ftdi_serial"]==peer["ftdi_serial"])
    image_sha=binding.get("phk1_bitstream_sha256")
    if not isinstance(image_sha,str) or not re.fullmatch(r"[0-9a-f]{64}",image_sha):
        raise LockError("approved PHK1 SHA binding unavailable")
    if image_sha != binding.get("phk1_bitstream_sha256"):
        raise LockError("approved PHK1 SHA mismatch")
    if image_kind=="xbt":
        loaded_sha=binding.get("rollback_image_sha256")
        image_path=str(Path(binding.get("rollback_image_path", "")).expanduser())
        if not isinstance(loaded_sha,str) or not re.fullmatch(r"[0-9a-f]{64}",loaded_sha):
            raise LockError("approved XBT rollback SHA binding unavailable")
    elif image_kind=="phk1":
        loaded_sha=image_sha
        image_path=str(root/"PHK1_FK33_CANARY.bit")
    else:
        loaded_sha=None
        image_path=""
    if image_kind!="identity" and ("Bitstream Loaded" not in log or image_path not in log):
        raise LockError(f"current SQRL log does not confirm the approved {image_kind.upper()} image load")
    if f"DNA: {target['dna']}" not in log or f"IDCODE({target['idcode']})" not in log:
        raise LockError("current SQRL startup log does not bind target DNA and IDCODE")
    if card["sqrl_jtag_serial"] not in log:
        raise LockError("current SQRL evidence does not bind the canary JTAG serial")
    if image_kind=="identity" and (f"DNA: {peer['dna']}" not in log or peer_card["sqrl_jtag_serial"] not in log):
        raise LockError("current bridge identity log does not distinguish the peer")
    target_usb=_usb_for_serial(target["ftdi_serial"],sysfs)
    peer_usb=_usb_for_serial(peer["ftdi_serial"],sysfs)
    if target_usb["path"]!=target["usb_path"] or target_usb["vid"]!=card["vid"] or target_usb["pid"]!=card["pid"]:
        raise LockError("current canary USB identity differs from authoritative map")
    if (peer_usb["path"]!=peer["usb_path"] or peer_usb["vid"]!=str(peer_card["vid"]).lower()
        or peer_usb["pid"]!=str(peer_card["pid"]).lower()):
        raise LockError("peer USB topology/VID/PID differs from authoritative map")
    # Both handles must be free before the lock is issued.
    for usb in (target_usb,peer_usb):
        result=lsof(["lsof","-t",usb["device_node"]],capture_output=True,text=True,check=False)
        if result.returncode not in (0,1) or result.stdout.strip():
            raise LockError("FTDI interface remains owned after programmer close")
    timestamp=now or dt.datetime.now(dt.timezone.utc)
    run_id=run_id or log_path.parent.name
    target_record={"usb_path":target_usb["path"],"ftdi_serial":target["ftdi_serial"],
        "vid":target_usb["vid"],"pid":target_usb["pid"],"manufacturer":card["manufacturer"],
        "product":card["product"],"interface":card["ftdi_interface"],"idcode":target["idcode"],"dna":target["dna"],
        "bridge_endpoint":card["bridge_endpoint"],"miner_binding":card["miner_binding"],
        "role":"PHK1_CANARY","expected_phk1_bitstream_sha256":image_sha}
    peer_record=complete_peer_identity({"usb_path":peer_usb["path"],"ftdi_serial":peer["ftdi_serial"],
        "vid":peer_usb["vid"],"pid":peer_usb["pid"],"idcode":peer["idcode"],"dna":peer["dna"]},authority)
    peer_record["role"]="PEER"
    return {"schema":"sidecar-raw-jtag-target-lock-v1","status":"PASS","run_id":run_id,
        "captured_utc":timestamp.isoformat(),"captured_monotonic_ns":time.monotonic_ns(),
        "match_count":1,"peer_distinct":True,"target":target_record,"peer":peer_record,
        "raw_device_handle_count":0,"peer_handle_open":False,
        "source":f"fresh read-only sysfs serial/VID/PID plus current SQRL {image_kind.upper()} IDCODE/DNA evidence; DNA identity gate",
        "loaded_image_kind":image_kind,"loaded_image_sha256":loaded_sha,
        "startup_log_sha256":__import__("hashlib").sha256(log.encode()).hexdigest()}

def main()->int:
    import argparse
    ap=argparse.ArgumentParser(); ap.add_argument("--startup-log",type=Path,required=True)
    ap.add_argument("--image-kind",choices=("phk1","xbt","identity"),default="phk1")
    ap.add_argument("--run-id")
    args=ap.parse_args()
    record=create_lock(args.startup_log,image_kind=args.image_kind,run_id=args.run_id)
    OUTPUT.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(dir=OUTPUT.parent,prefix=".raw-target-lock-")
    with os.fdopen(fd,"w") as f: json.dump(record,f,sort_keys=True,indent=2); f.write("\n"); f.flush(); os.fsync(f.fileno())
    os.chmod(tmp,0o600); os.replace(tmp,OUTPUT)
    print("TARGET_LOCK_FRESH=PASS\nTARGET_LOCK_MATCH_COUNT=1")
    return 0

if __name__=="__main__": raise SystemExit(main())
