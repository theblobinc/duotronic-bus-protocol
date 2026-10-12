from dataclasses import dataclass,field
@dataclass
class ConversationFederation:
    conversation_id:str;epoch:int=1;homes:set[str]=field(default_factory=set);sequence:int=0;max_homes:int=64
    def __post_init__(self):
        if not self.conversation_id or not 1<=self.epoch<=0xffffffffffffffff or not 0<=self.sequence<=0xffffffffffffffff or not 1<=self.max_homes<=4096:raise ValueError('federation state')
        if len(self.homes)>self.max_homes or any(not x for x in self.homes):raise ValueError('federation homes')
    def merge(self,remote_epoch:int,remote_sequence:int,remote_homes:set[str]):
        if not 1<=remote_epoch<=0xffffffffffffffff or not 0<=remote_sequence<=0xffffffffffffffff or any(not x for x in remote_homes):raise ValueError('remote federation state')
        if len(remote_homes)>self.max_homes:raise ValueError('remote federation home budget')
        if remote_epoch<self.epoch:return self
        if remote_epoch>self.epoch:
            self.epoch=remote_epoch;self.sequence=remote_sequence;self.homes=set(remote_homes);return self
        merged=self.homes|set(remote_homes)
        if len(merged)>self.max_homes:raise ValueError('federation home budget')
        self.sequence=max(self.sequence,remote_sequence);self.homes=merged;return self
    def advance(self):
        if self.sequence>=0xffffffffffffffff:raise OverflowError('federation sequence exhausted')
        self.sequence+=1;return self.sequence
