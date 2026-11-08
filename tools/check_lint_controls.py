#!/usr/bin/env python3
"""Real Clippy controls with exact diagnostic codes; never execute negative code."""
import argparse
from datetime import datetime,timezone
import hashlib,json,os
from pathlib import Path
import subprocess

LINTS=('unsafe_code','unused_must_use','clippy::unwrap_used','clippy::expect_used',
       'clippy::panic','clippy::todo','clippy::unimplemented','clippy::unreachable',
       'clippy::indexing_slicing','clippy::string_slice','clippy::arithmetic_side_effects',
       'clippy::as_conversions','clippy::dbg_macro')
CASES={
 'positive':('fn main(){let _value=1_i32.checked_div(0);}',None),
 'unsafe':('fn main(){unsafe {}}','unsafe_code'),
 'unused_result':('fn main(){Result::<(),()>::Err(());}','unused_must_use'),
 'unwrap':('fn value(x:Option<i32>)->i32{x.unwrap()} fn main(){let _x=value(Some(1));}','clippy::unwrap_used'),
 'expect':('fn value(x:Option<i32>)->i32{x.expect("fixture")} fn main(){let _x=value(Some(1));}','clippy::expect_used'),
 'panic':('fn main(){panic!("fixture");}','clippy::panic'),
 'todo':('fn main(){todo!();}','clippy::todo'),
 'unimplemented':('fn main(){unimplemented!();}','clippy::unimplemented'),
 'unreachable':('fn main(){unreachable!();}','clippy::unreachable'),
 'overflow':('fn value(a:i32)->i32{a+1} fn main(){let _x=value(1);}','clippy::arithmetic_side_effects'),
 'division':('fn value(a:i32,b:i32)->i32{a/b} fn main(){let _x=value(1,2);}','clippy::arithmetic_side_effects'),
 'index':('fn main(){let x=vec![1];let _v=x[0];}','clippy::indexing_slicing'),
 'string_slice':('fn main(){let x=String::from("abc");let _v=&x[0..1];}','clippy::string_slice'),
 'as_conversion':('fn value(x:i64)->i32{x as i32} fn main(){let _x=value(1);}','clippy::as_conversions'),
 'dbg':('fn main(){let _x=dbg!(1);}','clippy::dbg_macro'),
 'suppression':('#[allow(clippy::unwrap_used)] fn value(x:Option<i32>)->i32{x.unwrap()} fn main(){let _x=value(Some(1));}','E0453'),
 'unknown_lint':('#[allow(clippy::not_a_real_lint)] fn main(){}','unknown_lints'),
}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    root=Path(__file__).resolve().parents[1];out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    work=root/'build/lint-controls'/out.name;work.mkdir(parents=True,exist_ok=False)
    report=dict(status='RUNNING',cases=[],panic_absence='NOT_DEMONSTRATED',started_utc=datetime.now(timezone.utc).isoformat())
    env=dict(os.environ,CARGO_NET_OFFLINE='true',CARGO_INCREMENTAL='0',CARGO_TERM_COLOR='never')
    def run(name,command):
        r=subprocess.run(command,cwd=root,env=env,capture_output=True,timeout=120)
        (out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
        return r
    version=run('rustc',['rustc','--version','--verbose'])
    if version.returncode or not version.stdout.startswith(b'rustc 1.90.0 '):raise RuntimeError('pinned toolchain absent; not lint rejection')
    for name,(body,expected)in CASES.items():
        case=work/name;(case/'src').mkdir(parents=True)
        manifest=case/'Cargo.toml';manifest.write_text(f'[package]\nname="ab_{name}"\nversion="0.0.0"\nedition="2021"\n')
        source=case/'src/main.rs';source.write_text('#![forbid('+','.join(LINTS)+')]\n'+body+'\n')
        locked=run(name+'-lock',['cargo','generate-lockfile','--offline','--manifest-path',str(manifest)])
        if locked.returncode:raise RuntimeError('lock/bootstrap failure is not lint rejection')
        command=['cargo','clippy','--offline','--locked','--release','--manifest-path',str(manifest),
                 '--target-dir',str(work/'target'),'--message-format=json','--','-Dwarnings','-Dunknown_lints']+['-F'+v for v in LINTS]
        result=run(name,command);codes=[]
        for line in result.stdout.decode().splitlines():
            try:message=json.loads(line)
            except ValueError:continue
            if message.get('reason')=='compiler-message':
                code=message['message'].get('code')
                if code:codes.append(code['code'])
        passed=result.returncode==0 if expected is None else result.returncode!=0 and expected in codes
        record=dict(id=name,status='PASS'if passed else'FAIL',expected_code=expected,diagnostic_codes=codes,
                    exit_code=result.returncode,command=command,source_sha256=hashlib.sha256(source.read_bytes()).hexdigest())
        if expected is None and passed:
            executable=work/'target/release'/('ab_'+name)
            built=run('positive-build',['cargo','build','--offline','--locked','--release','--manifest-path',str(manifest),'--target-dir',str(work/'target')])
            if built.returncode:raise RuntimeError('positive build failed; not a lint negative')
            positive=run('positive-execution',[str(executable)])
            if positive.returncode:passed=False
            record['build_exit_code']=built.returncode
            record['execution_exit_code']=positive.returncode
            record['status']='PASS'if passed else'FAIL'
        report['cases'].append(record)
        import shutil
        shutil.copytree(case,out/'fixtures'/name)
        if not passed:report['status']='FAIL';break
    else:report['status']='PASS'
    report['finished_utc']=datetime.now(timezone.utc).isoformat()
    (out/'harness.py').write_bytes(Path(__file__).read_bytes());(out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    (out/'manifest.json').write_text(json.dumps({str(p.relative_to(out)):hashlib.sha256(p.read_bytes()).hexdigest()for p in out.rglob('*')if p.is_file()},indent=2)+'\n')
    print(json.dumps(dict(status=report['status'],cases=len(report['cases']))))
    return 0 if report['status']=='PASS'else 1


if __name__=='__main__':raise SystemExit(main())
