from dataclasses import dataclass
import hashlib,json
MAX_OBJECT_BYTES=(1<<63)-1
MAX_CHUNK_BYTES=16*1024*1024
MAX_CHUNKS=1_000_000

def digest(data:bytes)->str:return 'shake256-512:'+hashlib.shake_256(data).hexdigest(64)
def merkle_root(leaves:list[bytes])->str:
    if len(leaves)>MAX_CHUNKS:raise ValueError('too many Merkle leaves')
    if not leaves:return digest(b'')
    level=[hashlib.shake_256(b'DBP3/LEAF/v1'+x).digest(32) for x in leaves]
    while len(level)>1:
        if len(level)&1:level.append(level[-1])
        level=[hashlib.shake_256(b'DBP3/NODE/v1'+level[i]+level[i+1]).digest(32) for i in range(0,len(level),2)]
    return 'shake256-256:'+level[0].hex()
@dataclass(frozen=True)
class ObjectManifest:
    object_name:str;total_size:int;chunk_size:int;chunk_digests:tuple[str,...];media_type:str='application/octet-stream';merkle_root_id:str='';version:int=1;signer_ref:str='';predecessor_id:str=''
    def validate(self):
        if not self.object_name or len(self.object_name)>1024 or not self.media_type or len(self.media_type)>256:raise ValueError('object identity/media type')
        if not 0<=self.total_size<=MAX_OBJECT_BYTES or not 1<=self.chunk_size<=MAX_CHUNK_BYTES or not 1<=self.version<=0xffffffff:raise ValueError('size/version')
        expected=(self.total_size+self.chunk_size-1)//self.chunk_size if self.total_size else 0
        if expected!=len(self.chunk_digests) or len(self.chunk_digests)>MAX_CHUNKS:raise ValueError('chunk count')
        if any(not x or len(x)>256 for x in self.chunk_digests):raise ValueError('chunk digest')
        return self
    def object_id(self):
        self.validate();b=json.dumps(self.__dict__,sort_keys=True,separators=(',',':')).encode();return digest(b)
def build_manifest(name:str,data:bytes,chunk_size=65536,media_type='application/octet-stream',**kw):
    if len(data)>MAX_OBJECT_BYTES:raise ValueError('object too large')
    if not 1<=chunk_size<=MAX_CHUNK_BYTES:raise ValueError('chunk size')
    chunks=[data[i:i+chunk_size] for i in range(0,len(data),chunk_size)]
    if len(chunks)>MAX_CHUNKS:raise ValueError('too many chunks')
    m=ObjectManifest(name,len(data),chunk_size,tuple(digest(c) for c in chunks),media_type,merkle_root(chunks),**kw);m.validate();return m,chunks
def verify_chunk(manifest:ObjectManifest,index:int,data:bytes)->bool:
    manifest.validate()
    if not 0<=index<len(manifest.chunk_digests):return False
    expected=manifest.chunk_size if index<len(manifest.chunk_digests)-1 else manifest.total_size-manifest.chunk_size*(len(manifest.chunk_digests)-1)
    return len(data)==expected and digest(data)==manifest.chunk_digests[index]
