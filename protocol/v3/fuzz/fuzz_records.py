#!/usr/bin/env python3
import os,sys
sys.path.insert(0,os.path.join(os.path.dirname(__file__),'..','src'))
from dbp3.records import decode_records

def fuzz_one(data:bytes):
    for count in (0,1,2,8,128,129):
        try: decode_records(data,count)
        except Exception: pass
if __name__=='__main__': fuzz_one(sys.stdin.buffer.read())
