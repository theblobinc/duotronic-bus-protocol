from dataclasses import dataclass
@dataclass(frozen=True)
class PathMetric:
    path_id:int; rtt_ms:float; loss:float; jitter_ms:float; available_kbps:float; authenticated:bool=True; failure_domain:str=''
    def score(self):
        if not self.authenticated or self.loss>=1.0 or self.available_kbps<=0: return float('inf')
        return self.rtt_ms + 4*self.jitter_ms + 1000*self.loss + 1000/max(self.available_kbps,1)
def choose_paths(paths, *, critical=False, max_paths=2, independent_domains=False):
    good=sorted((p for p in paths if p.authenticated and p.loss<1.0 and p.available_kbps>0), key=lambda p:p.score())
    if not good: return []
    if not critical: return good[:1]
    if not independent_domains: return good[:max_paths]
    out=[]; seen=set()
    for p in good:
        domain=p.failure_domain or f'path:{p.path_id}'
        if domain in seen: continue
        out.append(p); seen.add(domain)
        if len(out)>=max_paths: break
    return out
