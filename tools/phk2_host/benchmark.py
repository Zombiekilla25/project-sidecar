"""Compare measured benchmark records without supplying default measurements."""
def compare(phk1:dict,phk2:dict)->dict:
    from schema import validate_benchmark
    validate_benchmark(phk1); validate_benchmark(phk2)
    a=phk1.get('work_items_per_sec'); b=phk2.get('work_items_per_sec')
    return {'schema':'PHK2-PHK1-Comparison-v1','phk1':phk1,'phk2':phk2,'throughput_ratio':(b/a if a and b is not None else None),'status':'MEASURED' if a and b is not None else 'INCOMPLETE'}
