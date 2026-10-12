from dataclasses import dataclass
@dataclass(frozen=True)
class PrivacyProfile:
    bucket_bps:int; max_batch_delay_ms:int; rotate_stream_after_frames:int; cover_enabled:bool=False
    def validate(self):
        if self.bucket_bps<0 or self.max_batch_delay_ms<0 or self.rotate_stream_after_frames<1: raise ValueError('privacy profile')
        return self

def pad_to_bucket(payload_len:int,bucket:int)->int:
    if payload_len<0 or bucket<1: raise ValueError('padding')
    return ((payload_len+bucket-1)//bucket)*bucket
