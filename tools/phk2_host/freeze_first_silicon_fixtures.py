"""Index current authoritative descriptor/CPU fixtures without rewriting them."""
from __future__ import annotations
import hashlib,json
from pathlib import Path
from board_protocol import encode_descriptor
from oracle import predict
from runtime import Descriptor,fixture_path,sha
from first_silicon_harness import oracle_record_sha

ROOT=Path(__file__).resolve().parents[2]
FIX=ROOT/"fixtures/phk2-host-runtime"
OUT=ROOT/"fixtures/phk2-first-silicon/descriptor-oracle-manifest-v1.json"

def main():
    manifest=json.loads((FIX/"authoritative-descriptors/manifest.json").read_text())
    records=[]
    for item in manifest["items"]:
        raw=(FIX/"authoritative-descriptors"/item["descriptor_file"]).read_bytes()
        d=Descriptor.decode(raw); answer=predict(d,0,1)
        if not answer.get("checks",{}).get("exact",False): raise RuntimeError(f"CPU oracle mismatch: {item['capture']}")
        records.append({"capture":item["capture"],"descriptor_path":str(Path("fixtures/phk2-host-runtime/authoritative-descriptors")/item["descriptor_file"]),"descriptor_sha256":sha(raw),"job_identity_hex":d.job_key.hex(),"job_identity_sha256":sha(d.job_key),"generation":d.generation,"seed_identity_sha256":sha(d.setup_seed64.to_bytes(8,"little")+d.noise_seed_A+d.noise_seed_B),"range":{"start":0,"count":1},"expected_result_count":1,"expected_raw_result_sha256":sha(answer["expected_compact_result"][0]),"expected_canonical_result_sha256":sha(answer["canonical_result"][0]),"cpu_oracle_sha256":oracle_record_sha(d,answer),"cpu_capture_result_count":len(answer["expected_compact_result"]),"cpu_capture_checks":answer["checks"]})
    d=Descriptor.decode((FIX/"authoritative-vector-001/descriptor.bin").read_bytes())
    batch=predict(d,0,64)
    if not batch.get("checks",{}).get("exact",False): raise RuntimeError("Batch64 oracle fixture mismatch")
    single=next(x for x in records if x["descriptor_sha256"]==sha(d.encode()))
    obj={"schema":"PHK2-FIRST-SILICON-FIXTURE-INDEX-v1","authority":{"host_runtime_commit":"6ec5e5ac959c169df3e706377e7287f9c55b3392","board_integration_commit":"1978750ef21471076d463d99166f3ab011269d14","wire_golden_sha256":sha((FIX/"wire-golden-v1.json").read_bytes())},"descriptor_bytes":112,"fixtures":{"single_work":single,"batch64":{"descriptor_path":"fixtures/phk2-host-runtime/authoritative-vector-001/descriptor.bin","descriptor_sha256":sha(d.encode()),"job_identity_hex":d.job_key.hex(),"job_identity_sha256":sha(d.job_key),"generation":d.generation,"seed_identity_sha256":sha(d.setup_seed64.to_bytes(8,"little")+d.noise_seed_A+d.noise_seed_B),"range":{"start":0,"count":64},"expected_result_count":64,"expected_raw_result_sha256":sha(b"".join(batch["expected_compact_result"])),"expected_canonical_result_sha256":sha(b"".join(batch["canonical_result"])),"cpu_oracle_sha256":oracle_record_sha(d,batch),"checks":batch["checks"]}},"retained_production_descriptors":records,"count":len(records)}
    OUT.parent.mkdir(parents=True,exist_ok=True); OUT.write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"output":str(OUT.relative_to(ROOT)),"retained_descriptors":len(records),"single_work_sha256":single["descriptor_sha256"],"batch64_sha256":obj["fixtures"]["batch64"]["descriptor_sha256"]},indent=2))
if __name__=="__main__":main()
