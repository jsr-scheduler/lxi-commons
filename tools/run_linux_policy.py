#!/usr/bin/env python3
"""Runs check_rust_policy's commands inside the Linux AArch64 builder image.

CHECKS_PASS=0 FAIL=1 NOT_RUN=2. A clean result never proves panic absence.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import check_rust_policy  # noqa: E402  (same directory, no third-party code)

BUILDER = 'localhost/ab-builder:1.90'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = dict(schema=1, status='NOT_RUN', target='linux', builder=BUILDER,
                  panic_proof='NOT_DEMONSTRATED', steps=[],
                  started_utc=datetime.now(timezone.utc).isoformat(),
                  lock_sha256=hashlib.sha256((ROOT / 'Cargo.lock').read_bytes()).hexdigest())
    code = 2
    podman = shutil.which('podman')
    try:
        if not podman:
            report['reason'] = 'podman not found'
            return code
        exists = subprocess.run([podman, 'image', 'exists', BUILDER], check=False)
        if exists.returncode != 0:
            report['reason'] = f'{BUILDER} missing: build containers/Containerfile.builder'
            return code
        report['builder_image_id'] = subprocess.run(
            [podman, 'image', 'inspect', BUILDER, '--format', '{{.Id}}'],
            capture_output=True, text=True, check=True).stdout.strip()
        target = ROOT / 'build/linux-policy/target'
        target.mkdir(parents=True, exist_ok=True)
        registry = Path.home() / '.cargo/registry'
        for index, argv in enumerate(check_rust_policy.commands('cargo', Path('/src/Cargo.toml')), 1):
            command = [podman, 'run', '--rm', '--network=none',
                       '-e', 'CARGO_TARGET_DIR=/target', '-e', 'CARGO_NET_OFFLINE=true',
                       '-e', 'CARGO_TERM_COLOR=never',
                       '-v', f'{ROOT}:/src:ro', '-v', f'{registry}:/usr/local/cargo/registry:ro',
                       '-v', f'{target}:/target', '-w', '/src', BUILDER, *argv]
            result = subprocess.run(command, capture_output=True, timeout=1800, check=False)
            stdout, stderr = out / f'{index:02d}.stdout.txt', out / f'{index:02d}.stderr.txt'
            stdout.write_bytes(result.stdout)
            stderr.write_bytes(result.stderr)
            report['steps'].append(dict(argv=command, returncode=result.returncode,
                                        stdout=stdout.name, stderr=stderr.name,
                                        stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),
                                        stderr_sha256=hashlib.sha256(result.stderr).hexdigest()))
            if result.returncode:
                report.update(status='FAIL', reason=f'step {index} failed; see its logs')
                code = 1
                return code
        if hashlib.sha256((ROOT / 'Cargo.lock').read_bytes()).hexdigest() != report['lock_sha256']:
            report.update(status='FAIL', reason='Cargo.lock changed during the checks')
            code = 1
            return code
        report.update(status='CHECKS_PASS', reason='all steps passed; panic absence NOT_DEMONSTRATED')
        code = 0
        return code
    finally:
        report['exit_code'] = code
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(f"{report['status']}: {report.get('reason', '')}")
        print(f'Report: {out / "result.json"}')


if __name__ == '__main__':
    sys.exit(main())
