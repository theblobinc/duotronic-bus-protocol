#!/usr/bin/env python3
import json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from dbp3 import constants as c
abi=json.loads((ROOT/'schemas/wire-abi.json').read_text())
assert abi['major']==c.MAJOR and abi['minor']==c.MINOR
assert abi['header_size']==c.HEADER_SIZE and abi['trailer_size']==c.TRAILER_SIZE and tuple(abi['frame_sizes'])==c.FRAME_SIZES
sizes={'u8':1,'u16':2,'u32':4,'u64':8}
for section,total in (('header_fields',c.HEADER_SIZE),('trailer_fields',c.TRAILER_SIZE)):
    occupied=[False]*total
    for name,off,width,kind in abi[section]:
        assert isinstance(off,int) and isinstance(width,int) and 0<=off and width>0 and off+width<=total,name
        if kind in sizes:assert sizes[kind]==width,(name,kind,width)
        assert not any(occupied[off:off+width]),name
        for i in range(off,off+width):occupied[i]=True
    assert all(occupied),f'{section} has undocumented gaps'
print('DBP3 ABI registry fully covers header/trailer and matches reference constants')
