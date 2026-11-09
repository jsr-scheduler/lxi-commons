#!/usr/bin/env python3
"""Runs lxi-pam's real-PAM tests inside the Linux AArch64 builder, as root.

Each run is a throwaway container without network: it creates the test accounts with a
random password generated inside it (never in these logs), a PAM service with pam_unix,
and runs the #[ignore] tests of crates/lxi-pam/tests/pam.rs in debug and release.
PASS=0 FAIL=1 NOT_RUN=2.
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
from run_linux_policy import BUILDER  # noqa: E402  (same directory)

SETUP = """set -eu
groupadd lxitesters
useradd -M -s /usr/sbin/nologin -G lxitesters lxitest
useradd -M -s /usr/sbin/nologin lxilocked
LXI_TEST_PAM_PASSWORD=$(head -c 18 /dev/urandom | base64)
export LXI_TEST_PAM_PASSWORD
printf 'lxitest:%s\\nlxilocked:%s\\n' "$LXI_TEST_PAM_PASSWORD" "$LXI_TEST_PAM_PASSWORD" | chpasswd
passwd -l lxilocked >/dev/null
printf 'auth required pam_unix.so\\naccount required pam_unix.so\\n' > /etc/pam.d/lxi-test
export LXI_TEST_PAM_SERVICE=lxi-test LXI_TEST_PAM_USER=lxitest LXI_TEST_PAM_GROUP=lxitesters
export LXI_TEST_PAM_LOCKED=lxilocked
"""

RUNS = [
    'cargo test --locked -p lxi-pam --test pam -- --ignored --test-threads=1',
    'cargo test --locked --release -p lxi-pam --test pam -- --ignored --test-threads=1',
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = dict(schema=1, status='NOT_RUN', target='linux', builder=BUILDER, steps=[],
                  started_utc=datetime.now(timezone.utc).isoformat(),
                  lock_sha256=hashlib.sha256((ROOT / 'Cargo.lock').read_bytes()).hexdigest())
    code = 2
    podman = shutil.which('podman')
    try:
        if not podman:
            report['reason'] = 'podman not found'
            return code
        if subprocess.run([podman, 'image', 'exists', BUILDER], check=False).returncode:
            report['reason'] = f'{BUILDER} missing: build containers/Containerfile.builder'
            return code
        report['builder_image_id'] = subprocess.run(
            [podman, 'image', 'inspect', BUILDER, '--format', '{{.Id}}'],
            capture_output=True, text=True, check=True).stdout.strip()
        target = ROOT / 'build/pam-it/target'
        target.mkdir(parents=True, exist_ok=True)
        registry = Path.home() / '.cargo/registry'
        for index, run in enumerate(RUNS, 1):
            command = [podman, 'run', '--rm', '--network=none', '--user', '0:0',
                       '-e', 'CARGO_TARGET_DIR=/target', '-e', 'CARGO_NET_OFFLINE=true',
                       '-e', 'CARGO_TERM_COLOR=never',
                       '-v', f'{ROOT}:/src:ro', '-v', f'{registry}:/usr/local/cargo/registry:ro',
                       '-v', f'{target}:/target', '-w', '/src', BUILDER,
                       'sh', '-c', SETUP + run]
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
            if b' 0 passed' in result.stdout or b'5 passed' not in result.stdout:
                report.update(status='FAIL', reason=f'step {index}: expected 5 tests to pass')
                code = 1
                return code
        report.update(status='PASS', reason='real PAM tests passed in debug and release')
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
