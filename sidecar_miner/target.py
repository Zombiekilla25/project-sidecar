"""PRL target conversion, matching local PearlHash miner and Rust consensus code."""
U256_MAX=(1<<256)-1

def compact_target(compact: int) -> int:
    exponent=(compact>>24)&0xff; mantissa=compact&0x007fffff
    if compact&0x00800000 or exponent==0 or mantissa==0: raise ValueError("invalid positive compact target")
    return mantissa << (8*(exponent-3)) if exponent>3 else mantissa >> (8*(3-exponent))

def target_to_compact(target: int) -> int:
    if isinstance(target,bool) or not isinstance(target,int) or not 0<target<=U256_MAX: raise ValueError("target outside positive U256")
    size=(target.bit_length()+7)//8
    mantissa=target << (8*(3-size)) if size<=3 else target >> (8*(size-3))
    if mantissa&0x800000: mantissa>>=8; size+=1
    compact=(size<<24)|mantissa
    if compact_target(compact)>target: raise AssertionError("compact target rounding weakened the target")
    return compact

def effective_share_target(pool_target: int, work_factor: int) -> int:
    """Official extract_difficulty_bound: raw compact target × tile_size × k, U256 saturating."""
    if not 0<pool_target<=U256_MAX: raise ValueError("pool target outside positive U256")
    if isinstance(work_factor,bool) or not isinstance(work_factor,int) or work_factor<=0: raise ValueError("work factor must be positive")
    return min(pool_target*work_factor,U256_MAX)

def compare_result(result_hash: int, target: int) -> bool:
    if isinstance(result_hash,bool) or not isinstance(result_hash,int) or not 0<=result_hash<=U256_MAX: raise ValueError("result hash outside U256")
    if not 0<target<=U256_MAX: raise ValueError("target outside positive U256")
    return result_hash<=target
