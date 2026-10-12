from dataclasses import dataclass
@dataclass(frozen=True)
class TimeState:
    source_time_us:int;observed_time_us:int;uncertainty_us:int=0;clock_ref:str='unspecified';clock_epoch:int=1
    def validate(self):
        if not (0<=self.source_time_us<=0xffffffffffffffff and 0<=self.observed_time_us<=0xffffffffffffffff and 0<=self.uncertainty_us<=0xffffffff):raise ValueError('time range')
        if not 1<=self.clock_epoch<=0xffffffff:raise ValueError('clock epoch one-origin/u32')
        if not self.clock_ref or len(self.clock_ref)>256:raise ValueError('clock_ref')
        return self
