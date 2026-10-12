from dataclasses import dataclass
from .errors import ReplayError
@dataclass
class ReplayWindow:
    width:int=256;highest:int=0;bitmap:int=0
    def __post_init__(self):
        if not isinstance(self.width,int) or not 1<=self.width<=65536:raise ReplayError('invalid replay window width')
        if self.highest<0 or self.highest>0xffffffffffffffff or self.bitmap<0:raise ReplayError('invalid replay state')
        self.bitmap &= (1<<self.width)-1
    def accept(self,sequence:int)->None:
        if not isinstance(sequence,int) or not 1<=sequence<=0xffffffffffffffff:raise ReplayError('sequence outside u64/one-origin range')
        if sequence>self.highest:
            shift=sequence-self.highest;self.bitmap=1 if shift>=self.width else ((self.bitmap<<shift)|1)&((1<<self.width)-1);self.highest=sequence;return
        delta=self.highest-sequence
        if delta>=self.width:raise ReplayError('sequence too old')
        bit=1<<delta
        if self.bitmap&bit:raise ReplayError('duplicate sequence')
        self.bitmap|=bit
