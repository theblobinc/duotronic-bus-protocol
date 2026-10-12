from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable,Protocol
import hashlib,json

class MergeResourceError(RuntimeError):pass

@dataclass(frozen=True)
class MergeItem:
    item_id:str;kind:str;sequence:int;size:int;payload:bytes=b'';priority:int=100;revoked:bool=False
@dataclass(frozen=True)
class MergeSegment:
    item_id:str;kind:str;sequence:int;offset:int;total_size:int;payload:bytes;priority:int;revoked:bool
@dataclass(frozen=True)
class MergeCursor:
    item_index:int=0;byte_offset:int=0;snapshot_digest:str=''
@dataclass(frozen=True)
class MergePage:
    items:tuple[MergeItem,...];next_cursor:int|None;bytes_used:int;yielded:bool;snapshot_digest:str=''
@dataclass(frozen=True)
class MergePageV2:
    segments:tuple[MergeSegment,...];next_cursor:MergeCursor|None;bytes_used:int;yielded:bool;snapshot_digest:str

_KIND_RANK={'revocation':0,'authority':1,'receipt':2,'command':3,'state':4,'message':5,'bulk':6}

def _validate_item(row:MergeItem,*,check_payload=True):
    if row.size<0 or (check_payload and row.size!=len(row.payload)):raise ValueError('merge item size')
    if row.sequence<1 or not row.item_id:raise ValueError('merge item identity')
    if not 0<=row.priority<=255:raise ValueError('merge item priority')
    return row

def _ordered(items:Iterable[MergeItem],*,max_snapshot_items:int=100_000)->list[MergeItem]:
    rows=[]
    for row in items:
        if len(rows)>=max_snapshot_items:raise MergeResourceError('in-memory merge snapshot item budget exceeded; use storage-backed MergeSnapshot')
        rows.append(_validate_item(row))
    return sorted(rows,key=lambda x:(_KIND_RANK.get(x.kind,99),x.priority,-int(x.revoked),x.sequence,x.item_id))

def _digest_rows(rows)->str:
    h=hashlib.sha256(b'DBP3/MERGE-SNAPSHOT/v3\0')
    for r in rows:
        meta=json.dumps([r.item_id,r.kind,r.sequence,r.size,r.priority,r.revoked],separators=(',',':')).encode()
        h.update(len(meta).to_bytes(4,'little'));h.update(meta);h.update(hashlib.sha256(r.payload).digest())
    return h.hexdigest()

class MergeSnapshot(Protocol):
    """Immutable storage-backed snapshot contract.

    Implementations may back this with a database/object store and MUST keep
    `snapshot_digest` stable for the life of every issued cursor. `read_segment`
    allows page reconciliation without materializing a whole historical item.
    """
    snapshot_digest:str
    total_items:int
    def item_meta(self,index:int)->MergeItem: ...
    def read_segment(self,index:int,offset:int,length:int)->bytes: ...

@dataclass(frozen=True)
class InMemoryMergeSnapshot:
    rows:tuple[MergeItem,...]
    snapshot_digest:str
    total_items:int
    @classmethod
    def from_items(cls,items:Iterable[MergeItem],*,max_snapshot_items:int=100_000):
        rows=tuple(_ordered(items,max_snapshot_items=max_snapshot_items));return cls(rows,_digest_rows(rows),len(rows))
    def item_meta(self,index:int)->MergeItem:
        r=self.rows[index];return MergeItem(r.item_id,r.kind,r.sequence,r.size,b'',r.priority,r.revoked)
    def read_segment(self,index:int,offset:int,length:int)->bytes:
        r=self.rows[index]
        if offset<0 or length<0 or offset+length>r.size:raise ValueError('merge segment read bounds')
        return r.payload[offset:offset+length]

def snapshot_digest(items:Iterable[MergeItem],*,max_snapshot_items:int=100_000)->str:
    return InMemoryMergeSnapshot.from_items(items,max_snapshot_items=max_snapshot_items).snapshot_digest

def reconcile_snapshot_page(snapshot:MergeSnapshot,*,cursor:MergeCursor|None=None,max_items:int=256,max_bytes:int=1_048_576)->MergePageV2:
    if max_items<1 or max_bytes<1:raise ValueError('merge bounds')
    if snapshot.total_items<0 or not snapshot.snapshot_digest:raise ValueError('merge snapshot')
    cur=cursor or MergeCursor(snapshot_digest=snapshot.snapshot_digest)
    if cur.snapshot_digest and cur.snapshot_digest!=snapshot.snapshot_digest:raise ValueError('merge snapshot changed; restart reconciliation')
    if cur.item_index<0 or cur.item_index>snapshot.total_items or cur.byte_offset<0:raise ValueError('merge cursor')
    out=[];used=0;i=cur.item_index;offset=cur.byte_offset
    while i<snapshot.total_items and len(out)<max_items and used<max_bytes:
        meta=_validate_item(snapshot.item_meta(i),check_payload=False)
        if offset>meta.size:raise ValueError('merge cursor offset')
        remaining=meta.size-offset;take=min(remaining,max_bytes-used)
        if meta.size==0:take=0
        if take==0 and remaining>0:break
        payload=snapshot.read_segment(i,offset,take)
        if len(payload)!=take:raise ValueError('snapshot returned short merge segment')
        out.append(MergeSegment(meta.item_id,meta.kind,meta.sequence,offset,meta.size,payload,meta.priority,meta.revoked));used+=take;offset+=take
        if offset>=meta.size:i+=1;offset=0
        if used>=max_bytes:break
    nxt=None if i>=snapshot.total_items else MergeCursor(i,offset,snapshot.snapshot_digest)
    return MergePageV2(tuple(out),nxt,used,nxt is not None,snapshot.snapshot_digest)

def reconcile_page(items:Iterable[MergeItem],*,cursor:MergeCursor|None=None,max_items:int=256,max_bytes:int=1_048_576,max_snapshot_items:int=100_000)->MergePageV2:
    snap=InMemoryMergeSnapshot.from_items(items,max_snapshot_items=max_snapshot_items)
    return reconcile_snapshot_page(snap,cursor=cursor,max_items=max_items,max_bytes=max_bytes)

def bounded_reconcile(items:Iterable[MergeItem],*,cursor:int=0,max_items:int=256,max_bytes:int=1_048_576,max_snapshot_items:int=100_000)->MergePage:
    if cursor<0 or max_items<1 or max_bytes<1:raise ValueError('merge bounds')
    rows=_ordered(items,max_snapshot_items=max_snapshot_items);digest=_digest_rows(rows);out=[];used=0;i=cursor
    while i<len(rows) and len(out)<max_items:
        row=rows[i]
        if row.size>max_bytes and not out:raise ValueError('single merge item exceeds legacy page byte budget; use reconcile_snapshot_page')
        if used+row.size>max_bytes:break
        out.append(row);used+=row.size;i+=1
    nxt=i if i<len(rows) else None
    return MergePage(tuple(out),nxt,used,nxt is not None,digest)
