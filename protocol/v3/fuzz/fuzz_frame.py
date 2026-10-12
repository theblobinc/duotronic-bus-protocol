#!/usr/bin/env python3
import os,sys
sys.path.insert(0,os.path.join(os.path.dirname(__file__),'..','src'))
from dbp3 import decode_frame

def fuzz_one(data:bytes):
    try: decode_frame(data)
    except Exception: pass
if __name__=='__main__':
    fuzz_one(sys.stdin.buffer.read())
