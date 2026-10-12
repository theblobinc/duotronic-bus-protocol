def validate_expansion(*, compressed_bytes:int, declared_plain_bytes:int, max_plain_bytes:int, max_ratio:int)->None:
    if min(compressed_bytes,declared_plain_bytes,max_plain_bytes,max_ratio) < 0 or max_ratio < 1: raise ValueError('compression bounds')
    if declared_plain_bytes > max_plain_bytes: raise ValueError('decompressed size budget')
    if compressed_bytes == 0:
        if declared_plain_bytes: raise ValueError('impossible compression declaration')
        return
    if declared_plain_bytes > compressed_bytes * max_ratio: raise ValueError('decompression expansion ratio')
