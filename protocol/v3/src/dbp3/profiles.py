from dataclasses import dataclass
from .constants import FRAME_SIZES
@dataclass(frozen=True)
class ProfileLimits:
    max_records_per_frame:int=64; max_fragmented_messages:int=128; max_reassembly_bytes:int=16*1024*1024; max_object_bytes:int=4*1024*1024*1024; replay_window:int=512; max_fec_n:int=64; max_group_members:int=1024; max_clock_uncertainty_us:int=5_000_000; allowed_frame_sizes:tuple[int,...]=FRAME_SIZES; max_decompression_ratio:int=64
UTM_PROFILE=ProfileLimits(max_records_per_frame=48,max_fragmented_messages=256,max_reassembly_bytes=64*1024*1024,replay_window=1024,max_fec_n=96,max_group_members=4096,max_decompression_ratio=32)
WGRNN_PROFILE=ProfileLimits(max_records_per_frame=64,max_fragmented_messages=128,max_reassembly_bytes=128*1024*1024,replay_window=2048,max_fec_n=64,max_group_members=1024,max_decompression_ratio=16)
