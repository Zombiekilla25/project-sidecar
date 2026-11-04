from __future__ import annotations
from collections import defaultdict

def assign_batches(batch_count:int,fk_count:int,policy:str):
    if batch_count<0 or fk_count<1:raise ValueError('invalid batch/fleet count')
    if policy not in ('round_robin','least_loaded','batch_partition'):raise ValueError('unsupported assignment policy')
    out=[[] for _ in range(fk_count)]; loads=[0]*fk_count
    if policy=='batch_partition':
        for i in range(batch_count):out[min(fk_count-1,i*fk_count//max(1,batch_count))].append(i)
    elif policy=='round_robin':
        for i in range(batch_count):out[i%fk_count].append(i);loads[i%fk_count]+=1
    else:
        for i in range(batch_count):
            j=min(range(fk_count),key=lambda x:(loads[x],x));out[j].append(i);loads[j]+=1
    return out

def fleet_time_us(batch_count:int,fk_count:int,fixed_us:float,per_item_us:float,policy='batch_partition'):
    if fixed_us<0 or per_item_us<0:raise ValueError('timings must be nonnegative')
    assigned=assign_batches(batch_count,fk_count,policy)
    return max((fixed_us+len(x)*per_item_us for x in assigned if x),default=0.0)
