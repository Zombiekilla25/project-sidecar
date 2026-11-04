from __future__ import annotations
import argparse,json
from .timing import TimingRecord
from .model import account,decide,simulate_batch_sizes,recommended_batch,break_even_batch
from .fleet import fleet_time_us

def _num(v):return round(v,3) if v is not None else None

def main(argv=None):
    p=argparse.ArgumentParser(prog='sidecar-bench-model')
    sub=p.add_subparsers(dest='command',required=True)
    c=sub.add_parser('compare'); c.add_argument('gpu');c.add_argument('fk')
    b=sub.add_parser('batch-sweep');b.add_argument('gpu');b.add_argument('fk')
    f=sub.add_parser('fleet');f.add_argument('--fk-count',type=int,choices=(1,2,4,8),required=True);f.add_argument('fk');f.add_argument('--batches',type=int,default=64);f.add_argument('--policy',choices=('round_robin','least_loaded','batch_partition'),default='batch_partition')
    a=p.parse_args(argv)
    if a.command in ('compare','batch-sweep'):
        gpu=TimingRecord.load(a.gpu,'gpu');fk=TimingRecord.load(a.fk,'fk');acc=account(gpu,fk);decision=decide(gpu,fk)
        out={'gpu_only_total_us':_num(acc.gpu_only_total_us),'sidecar_total_us':_num(acc.sidecar_total_us),'sidecar_speedup':_num(acc.sidecar_speedup),'transfer_percent':_num(acc.transfer_percent),'fpga_compute_percent':_num(acc.fpga_compute_percent),'host_overhead_percent':_num(acc.host_overhead_percent),'break_even_transfer_time_us':_num(acc.break_even_transfer_time_us),'end_to_end_throughput_items_s':_num(acc.end_to_end_throughput_items_s),'decision':decision.value,'gpu_source':gpu.source,'fk_source':fk.source,'measured_comparison':gpu.measured and fk.measured}
        if a.command=='batch-sweep':
            gv=gpu.values;fv=fk.values
            needed=(gv.get('total_us'),gv.get('batch_size'),fv.get('batch_size'),fv.get('program_time_us'),fv.get('backend_open_us'),fv.get('target_revalidation_us'),fv.get('hello_us'),fv.get('host_pack_us'),fv.get('input_stream_us'),fv.get('fpga_compute_us'),fv.get('output_stream_us'),fv.get('host_compose_us'),fv.get('verify_us'))
            if all(x is not None for x in needed):
                fixed=sum(fv[k] for k in ('program_time_us','backend_open_us','target_revalidation_us','hello_us'))
                divisor=fv['batch_size']
                transport=(fv['input_stream_us']+fv['output_stream_us'])/divisor
                compute=fv['fpga_compute_us']/divisor
                verify=fv['verify_us']/divisor
                host=(fv['host_pack_us']+fv['host_compose_us'])/divisor
                preds=simulate_batch_sizes(gv['total_us'],gv['batch_size'],fixed,transport,compute,verify,host_per_item_us=host)
                out['batch_predictions']=[{'batch_size':x.batch_size,'predicted_total_us':_num(x.predicted_total_us),'predicted_throughput_items_s':_num(x.throughput_items_s),'speedup_vs_gpu_only':_num(x.speedup_vs_gpu_only)} for x in preds]
                gpu_per_item=gv['total_us']/gv['batch_size']
                fk_per_item=transport+compute+verify+host
                out['break_even_batch_size']=break_even_batch(gpu_per_item,fixed,fk_per_item)
                out['recommended_batch_size']=recommended_batch(preds);out['predictions_are_simulated']=True
            else:out['batch_predictions']=None;out['recommended_batch_size']=None;out['break_even_batch_size']=None;out['predictions_are_simulated']=None
    else:
        fk=TimingRecord.load(a.fk,'fk');v=fk.values
        setup_keys=('program_time_us','backend_open_us','target_revalidation_us','hello_us')
        can_model=v.get('vector_total_us') is not None and v.get('batch_size') and all(v.get(k) is not None for k in setup_keys)
        if not can_model:out={'fleet_time_us':None,'decision':'INSUFFICIENT_DATA','recommended_fk_count':None,'fleet_predictions_us':None}
        else:
            fixed=sum(v[k] for k in setup_keys)
            per_batch=max(0.0,(v['vector_total_us']-fixed)/v['batch_size'])
            predictions={str(n):fleet_time_us(a.batches,n,fixed,per_batch,a.policy) for n in (1,2,4,8)}
            best=min((float(t),int(n)) for n,t in predictions.items())[1]
            out={'fleet_time_us':_num(predictions[str(a.fk_count)]),'fk_count':a.fk_count,'policy':a.policy,'decision':'INSUFFICIENT_DATA','recommended_fk_count':best,'fleet_predictions_us':{k:_num(vv) for k,vv in predictions.items()},'predictions_are_simulated':True,'measured_fleet_timing':False,'source':fk.source}
    print(json.dumps(out,sort_keys=True,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
