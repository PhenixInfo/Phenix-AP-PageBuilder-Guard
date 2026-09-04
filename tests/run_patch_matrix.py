#!/usr/bin/env python3
import glob, json, pathlib, shutil, subprocess, sys, tempfile, zipfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
archives = sys.argv[1] if len(sys.argv)>1 else str(ROOT/'fixtures')
files = sorted(glob.glob(str(pathlib.Path(archives)/'*.zip')))
wanted = ['2.4.1','2.4.3','2.4.5','2.4.8']
selected=[]
for version in wanted:
    matches=[p for p in files if version.replace('.','') in pathlib.Path(p).name.replace('.','')]
    if matches: selected.append((version,matches[0]))
if len(selected)!=len(wanted):
    print('Missing real AP archives. Need:', ', '.join(wanted)); sys.exit(2)
for version,zpath in selected:
    with tempfile.TemporaryDirectory(prefix='ap-matrix-') as tmp:
        tmp=pathlib.Path(tmp); ps=tmp/'ps'; mods=ps/'modules'; mods.mkdir(parents=True)
        with zipfile.ZipFile(zpath) as z: z.extractall(mods)
        if not (mods/'appagebuilder').is_dir():
            dirs=[p for p in mods.iterdir() if p.is_dir()]
            if len(dirs)==1: dirs[0].rename(mods/'appagebuilder')
        cp=subprocess.run(['php',str(ROOT/'tests/patch_case.php'),str(ps),str(ROOT/'module')],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if cp.returncode: print(version,cp.stderr); sys.exit(1)
        data=json.loads(cp.stdout)
        if data['before'] != data['afterRollback']:
            print(version,'FAIL rollback hash mismatch'); sys.exit(1)
        if data['after1'] != data['after2']:
            print(version,'FAIL second patch not idempotent'); sys.exit(1)
        if not data.get('manualSnapshot') or data.get('afterManualRestore') != data['before']:
            print(version,'FAIL manual backup/restore hash mismatch'); sys.exit(1)
        if any(x['rc'] for x in data['lint'].values()):
            print(version,'FAIL lint',data['lint']); sys.exit(1)
        print(version,'OK detected='+str(data['version']),'manual-restore=exact')
print('patch matrix: OK')
