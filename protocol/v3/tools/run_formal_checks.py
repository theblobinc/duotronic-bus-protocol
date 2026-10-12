#!/usr/bin/env python3
from __future__ import annotations
import argparse,os,pathlib,shutil,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]

def run(cmd,**kwargs):
    print('+',' '.join(map(str,cmd)))
    subprocess.run(list(map(str,cmd)),check=True,cwd=ROOT,**kwargs)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--strict',action='store_true');a=ap.parse_args()
    jar=os.environ.get('TLA2TOOLS_JAR','')
    lean=shutil.which('lean')
    if not jar or not pathlib.Path(jar).exists():
        if a.strict: raise SystemExit('strict formal gate: TLA2TOOLS_JAR is unavailable')
        print('TLA+ tools unavailable: syntax/model checks skipped locally')
    else:
        for tla in sorted((ROOT/'formal').glob('*.tla')):
            run(['java','-cp',jar,'tla2sany.SANY',str(tla)])
        for cfg_path in sorted((ROOT/'formal').glob('*.cfg')):
            model=cfg_path.with_suffix('.tla')
            if not model.exists(): raise SystemExit(f'missing TLA+ model for {cfg_path.name}')
            run(['java','-cp',jar,'tlc2.TLC','-deadlock','-config',str(cfg_path),str(model)])
    lean_files=sorted((ROOT/'formal/lean').glob('*.lean'))
    if not lean:
        if a.strict: raise SystemExit('strict formal gate: Lean executable unavailable')
        print('Lean unavailable: proof compilation skipped locally')
    else:
        for f in lean_files: run([lean,str(f)])
    print('formal tool gate completed')
if __name__=='__main__': main()
