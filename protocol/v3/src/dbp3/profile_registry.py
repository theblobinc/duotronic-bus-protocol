from __future__ import annotations
from dataclasses import dataclass
import hashlib,json
from pathlib import Path
from .resource_budget import ResourceLimits,AdmissionRequest,AdmissionEstimate,RuntimeKind,PlatformLimits,require_runtime_admission,require_platform_admission
class ProfileError(ValueError):pass

@dataclass(frozen=True)
class ResolvedProfile:
    profile_id:int;name:str;closure:tuple[str,...];record_names:frozenset[str];features:frozenset[str];frame_sizes:tuple[int,...]
    security_suite:str;security_suite_id:int;security_suite_status:str;protected:bool
    fec_policy:str;fec_algorithm:str;fec_algorithm_id:int;fec_min_k:int;fec_max_n:int
    max_records:int;replay_window:int;resource_class:str;requires:frozenset[str];production:bool;manifest_digest:str
    def manifest(self)->dict:
        return {'schema':'dbp3-resolved-profile/v2','profile_id':self.profile_id,'name':self.name,'closure':list(self.closure),
         'record_names':sorted(self.record_names),'features':sorted(self.features),'frame_sizes':list(self.frame_sizes),
         'security_suite':self.security_suite,'security_suite_id':self.security_suite_id,'security_suite_status':self.security_suite_status,
         'protected':self.protected,'fec_policy':self.fec_policy,'fec_algorithm':self.fec_algorithm,'fec_algorithm_id':self.fec_algorithm_id,
         'fec_min_k':self.fec_min_k,'fec_max_n':self.fec_max_n,'max_records':self.max_records,'replay_window':self.replay_window,
         'resource_class':self.resource_class,'requires':sorted(self.requires),'production':self.production,'digest':self.manifest_digest}
@dataclass(frozen=True)
class ActiveProfile:
    resolved:ResolvedProfile;runtime:RuntimeKind;admission:AdmissionEstimate

class ProfileRegistry:
    def __init__(self,docs:dict[str,dict],*,security_suites=None,fec_policies=None,fec_algorithms=None,known_record_names=None):
        self.docs=docs;self.security_suites=security_suites or {};self.fec_policies=fec_policies or {};self.fec_algorithms=fec_algorithms or {};self.known_record_names=known_record_names
    @classmethod
    def from_directory(cls,path:Path|str):
        path=Path(path);docs={}
        for p in path.glob('*.json'):
            if p.name in {'registry.json','privacy.json','resilience.json'}:continue
            d=json.loads(p.read_text());name=d.get('name')
            if name:docs[name]=d
        root=path.parent
        suites={x['name']:x for x in json.loads((root/'registries/security-suites.json').read_text()).get('suites',[])}
        policies={x['name']:x for x in json.loads((root/'registries/fec-policies.json').read_text()).get('policies',[])}
        algs={x['name']:x for x in json.loads((root/'schemas/algorithm-registry.json').read_text()).get('fec',[])}
        known=set(json.loads((root/'schemas/record-registry.json').read_text()).get('records',{}).values())
        return cls(docs,security_suites=suites,fec_policies=policies,fec_algorithms=algs,known_record_names=known)
    @staticmethod
    def _digest(payload:dict)->str:return hashlib.sha256(b'DBP3/RESOLVED-PROFILE/v2\0'+json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    def _fec_refines(self,child:str,parent:str)->bool:
        if child==parent:return True
        seen=set();cur=child
        while cur and cur not in seen:
            seen.add(cur);row=self.fec_policies.get(cur,{}) ;cur=row.get('extends')
            if cur==parent:return True
        return False
    def resolve(self,name:str,*,allow_experimental:bool=False)->ResolvedProfile:
        visiting=set();seen=[];records=set();features=set();requires=set();frame_sizes=None
        suite=None;protected=False;fec_policy=None;max_records=None;replay_window=None;resource_class='standard';production=True
        def walk(n):
            nonlocal frame_sizes,suite,protected,fec_policy,max_records,replay_window,resource_class,production
            if n in seen:return
            if n in visiting:raise ProfileError(f'profile dependency cycle at {n}')
            if n not in self.docs:raise ProfileError(f'unknown profile dependency: {n}')
            visiting.add(n);d=self.docs[n]
            for parent in d.get('extends',[]):walk(parent)
            visiting.remove(n);seen.append(n)
            required=('id','name','protected','suite','fec','max_records','replay_window','frame_sizes')
            miss=[x for x in required if x not in d]
            if miss:raise ProfileError(f'{n} missing required fields: {miss}')
            pid=d['id']
            if not isinstance(pid,int) or not 1<=pid<=65535:raise ProfileError(f'{n} profile id outside u16')
            if protected and not d['protected']:raise ProfileError('protected parent cannot be weakened')
            protected=protected or bool(d['protected'])
            ds=d['suite']
            if suite is not None and suite!=ds:raise ProfileError('security-suite conflict in profile closure')
            suite=ds
            fp=d['fec']
            if fp not in self.fec_policies:raise ProfileError(f'unregistered FEC policy: {fp}')
            if fec_policy is not None and fec_policy!=fp:
                if self._fec_refines(fp,fec_policy):fec_policy=fp
                elif not self._fec_refines(fec_policy,fp):raise ProfileError('incompatible FEC policy change in profile closure')
            else:fec_policy=fp
            mr=int(d['max_records']);rw=int(d['replay_window'])
            if not 1<=mr<=128 or not 32<=rw<=65536:raise ProfileError('invalid operational limits')
            max_records=mr if max_records is None else min(max_records,mr);replay_window=rw
            resource_class=d.get('resource_class',resource_class);production=production and bool(d.get('production',True))
            records.update(d.get('record_names',[]));features.update(d.get('features',[]));requires.update(d.get('requires',[]))
            fs=tuple(int(x) for x in d.get('frame_sizes',()))
            if not fs or len(set(fs))!=len(fs) or any(x not in (256,512,1024,2048,4096) for x in fs):raise ProfileError('unsupported frame-size declaration')
            frame_sizes=fs if frame_sizes is None else tuple(x for x in frame_sizes if x in fs)
        walk(name)
        if not frame_sizes:raise ProfileError('profile closure has no common frame size')
        if self.known_record_names is not None:
            unknown=records-self.known_record_names
            if unknown:raise ProfileError(f'unregistered record names in profile closure: {sorted(unknown)}')
        if suite not in self.security_suites:raise ProfileError(f'unregistered security suite: {suite}')
        sr=self.security_suites[suite];status=sr.get('status')
        if status in {'deprecated','forbidden'}:raise ProfileError(f'invalid security suite status: {status}')
        if status=='experimental' and not allow_experimental:raise ProfileError('experimental suite requires explicit opt-in')
        if protected and not sr.get('production',False) and not allow_experimental:raise ProfileError('protected production profile requires production security suite')
        fr=self.fec_policies[fec_policy]
        if fr.get('status') in {'deprecated','forbidden'}:raise ProfileError('invalid FEC policy status')
        alg=fr['algorithm']
        if alg not in self.fec_algorithms:raise ProfileError(f'unregistered FEC algorithm: {alg}')
        ar=self.fec_algorithms[alg]
        if int(ar['id'])>255:raise ProfileError('FEC algorithm id exceeds wire u8')
        payload={'profile_id':int(self.docs[name]['id']),'name':name,'closure':seen,'record_names':sorted(records),'features':sorted(features),
         'frame_sizes':list(frame_sizes),'security_suite':suite,'security_suite_id':int(sr['id']),'security_suite_status':status,'protected':protected,
         'fec_policy':fec_policy,'fec_algorithm':alg,'fec_algorithm_id':int(ar['id']),'fec_min_k':int(fr['min_k']),'fec_max_n':int(fr['max_n']),
         'max_records':max_records,'replay_window':replay_window,'resource_class':resource_class,'requires':sorted(requires),'production':production}
        digest=self._digest(payload)
        return ResolvedProfile(payload['profile_id'],name,tuple(seen),frozenset(records),frozenset(features),tuple(frame_sizes),suite,int(sr['id']),status,protected,
          fec_policy,alg,int(ar['id']),int(fr['min_k']),int(fr['max_n']),max_records,replay_window,resource_class,frozenset(requires),production,digest)
    def activate(self,name:str,*,runtime:RuntimeKind|str,limits:ResourceLimits,request:AdmissionRequest|None=None,platform:PlatformLimits|None=None,allow_experimental:bool=False)->ActiveProfile:
        resolved=self.resolve(name,allow_experimental=allow_experimental)
        if request is None:
            fk=0 if resolved.fec_algorithm=='none' else max(1,resolved.fec_min_k,8)
            fn=0 if resolved.fec_algorithm=='none' else min(resolved.fec_max_n,max(fk,12))
            request=AdmissionRequest(frame_size=max(resolved.frame_sizes),max_records=resolved.max_records,concurrent_sessions=4,
             inflight_messages=min(32,limits.inflight_messages),fec_k=fk,fec_n=fn,fec_groups=min(8,limits.fec_groups),
             group_fanout=min(16,limits.fanout_targets),merge_page_bytes=min(1024*1024,max(1,limits.memory_bytes//8)),
             merge_items=min(128,limits.merge_items),mailbox_items=min(64,limits.mailbox_items))
        if request.frame_size not in resolved.frame_sizes:raise ProfileError('admission frame size not permitted by resolved profile')
        if request.max_records>resolved.max_records:raise ProfileError('admission max_records exceeds resolved profile')
        if resolved.fec_algorithm=='none':
            if request.fec_k or request.fec_n:raise ProfileError('FEC requested by no-FEC profile')
        else:
            if request.fec_k<resolved.fec_min_k or request.fec_n>resolved.fec_max_n:raise ProfileError('FEC request outside resolved policy bounds')
        estimate=require_runtime_admission(request,limits,runtime)
        if platform is not None:require_platform_admission(request,estimate,platform)
        return ActiveProfile(resolved,RuntimeKind(runtime),estimate)
    def accepts_record(self,name:str,record_name:str,critical:bool=False)->bool:
        r=self.resolve(name)
        if record_name in r.record_names:return True
        if critical:raise ProfileError(f'unsupported critical record {record_name} for {name}')
        return False
