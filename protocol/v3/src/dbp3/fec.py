"""Small systematic GF(256) erasure-code reference.

Conformance/reference implementation, not an optimized production codec. FEC
never silently downgrades protected traffic.  Admission has both workspace and
work-unit bounds so a slower runtime cannot remain indefinitely inside an
otherwise-valid recovery operation.
"""
PRIM=0x11d
EXP=[0]*512;LOG=[0]*256
x=1
for i in range(255):
    EXP[i]=x;LOG[x]=i;x<<=1
    if x&0x100:x^=PRIM
for i in range(255,512):EXP[i]=EXP[i-255]

class FECWorkspaceError(RuntimeError):pass
class FECWorkLimitError(RuntimeError):pass

def estimate_workspace_bytes(k:int,n:int,shard_size:int)->int:
    if not (1<=k<=n<=255):raise ValueError('require 1 <= k <= n <= 255')
    if shard_size<1:raise ValueError('shard size must be positive')
    return 4096+(k*shard_size*2)+(n*shard_size)+(k*k*2)

def estimate_encode_work_units(k:int,n:int,shard_size:int)->int:
    if not (1<=k<=n<=255) or shard_size<1: raise ValueError('FEC dimensions')
    return (n-k)*k*shard_size

def estimate_recover_work_units(k:int,n:int,shard_size:int)->int:
    if not (1<=k<=n<=255) or shard_size<1: raise ValueError('FEC dimensions')
    # Gaussian elimination plus reconstruction; intentionally conservative.
    return 4*k*k*k + k*k*shard_size

def require_workspace(k:int,n:int,shard_size:int,workspace_bytes:int|None)->int:
    need=estimate_workspace_bytes(k,n,shard_size)
    if workspace_bytes is not None and (not isinstance(workspace_bytes,int) or workspace_bytes<need):
        raise FECWorkspaceError(f'FEC workspace insufficient: need {need}, have {workspace_bytes}')
    return need

def require_work_units(need:int,max_work_units:int|None)->int:
    if max_work_units is not None and (not isinstance(max_work_units,int) or max_work_units<need):
        raise FECWorkLimitError(f'FEC work budget insufficient: need {need}, have {max_work_units}')
    return need

def mul(a,b):
    if not a or not b:return 0
    return EXP[LOG[a]+LOG[b]]
def inv(a):
    if not a:raise ZeroDivisionError
    return EXP[255-LOG[a]]
def powg(a,n):
    if n==0:return 1
    if a==0:return 0
    return EXP[(LOG[a]*n)%255]
def _mat_inv(a):
    n=len(a);m=[row[:]+[1 if i==j else 0 for j in range(n)] for i,row in enumerate(a)]
    for c in range(n):
        p=next((r for r in range(c,n) if m[r][c]),None)
        if p is None:raise ValueError('singular FEC matrix')
        m[c],m[p]=m[p],m[c];q=inv(m[c][c]);m[c]=[mul(v,q) for v in m[c]]
        for r in range(n):
            if r==c or not m[r][c]:continue
            q=m[r][c];m[r]=[v^mul(q,w) for v,w in zip(m[r],m[c])]
    return [row[n:] for row in m]
def _row(index,k):
    if index<k:return [1 if j==index else 0 for j in range(k)]
    base=(index-k)+1;return [powg(base,j) for j in range(k)]

def encode(data_shards:list[bytes],n:int,*,workspace_bytes:int|None=None,max_work_units:int|None=None)->list[bytes]:
    k=len(data_shards)
    if not (1<=k<=n<=255):raise ValueError('require 1 <= k <= n <= 255')
    size=len(data_shards[0]) if data_shards else 0
    if size<1:raise ValueError('empty shards are not a valid FEC group')
    if any(len(s)!=size for s in data_shards):raise ValueError('shard sizes differ')
    require_workspace(k,n,size,workspace_bytes);require_work_units(estimate_encode_work_units(k,n,size),max_work_units)
    out=list(data_shards)
    for idx in range(k,n):
        row=_row(idx,k);p=bytearray(size)
        for j,s in enumerate(data_shards):
            c=row[j]
            if c:
                for z,b in enumerate(s):p[z]^=mul(c,b)
        out.append(bytes(p))
    return out

def recover(available:dict[int,bytes],k:int,n:int,*,workspace_bytes:int|None=None,max_work_units:int|None=None)->list[bytes]:
    if not (1<=k<=n<=255):raise ValueError('bad k/n')
    if len(available)<k:raise ValueError('not enough shards')
    chosen=sorted(available)[:k]
    if any(i<0 or i>=n for i in chosen):raise ValueError('bad shard index')
    size=len(available[chosen[0]])
    if size<1:raise ValueError('empty shards are not a valid FEC group')
    if any(len(available[i])!=size for i in chosen):raise ValueError('shard sizes differ')
    require_workspace(k,n,size,workspace_bytes);require_work_units(estimate_recover_work_units(k,n,size),max_work_units)
    a=[_row(i,k) for i in chosen];ai=_mat_inv(a);data=[bytearray(size) for _ in range(k)]
    for out_i in range(k):
        for src_i,idx in enumerate(chosen):
            c=ai[out_i][src_i]
            if c:
                s=available[idx]
                for z,b in enumerate(s):data[out_i][z]^=mul(c,b)
    return [bytes(x) for x in data]
