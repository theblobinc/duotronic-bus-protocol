from dataclasses import dataclass
@dataclass(frozen=True)
class MediaCorrelation:
    track_id:str; media_timestamp:int; timebase_num:int; timebase_den:int; source_witness_id:str; telemetry_message_id:int=0
    def validate(self):
        if not self.track_id or not self.source_witness_id or self.timebase_num<1 or self.timebase_den<1 or self.media_timestamp<0: raise ValueError('media correlation')
        if self.telemetry_message_id<0: raise ValueError('telemetry message id')
        return self
