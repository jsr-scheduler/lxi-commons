#!/usr/bin/env python3
"""cargo-deny (advisories, licenses, bans, sources) in a pinned container.

PASS=0 FAIL=1 NOT_RUN=2. The image and cargo-deny's version are pinned so the gate
cannot change under us; the advisory database is fetched fresh on every run.
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
# rust:1-slim (multi-architecture index), pinned: the gate itself must not change under us.
IMAGE = 'docker.io/library/rust@sha256:1a939748a7cbab172de91a014e3804a97af1394a8c844faa67fce9401c4e40fb'
DENY = 'cargo-deny@0.20.2'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = dict(schema=1, status='NOT_RUN', image=IMAGE, tool=DENY,
                  started_utc=datetime.now(timezone.utc).isoformat(),
                  lock_sha256=hashlib.sha256((ROOT / 'Cargo.lock').read_bytes()).hexdigest())
    code = 2
    podman = shutil.which('podman')
    try:
        if not podman:
            report['reason'] = 'podman not found'
            return code
        script = ('command -v git >/dev/null || (apt-get update -qq && apt-get install -y -qq git >/dev/null); '
                  'rm -rf /usr/local/cargo/advisory-dbs; '
                  f'[ -x /opt/deny/bin/cargo-deny ] || cargo install --locked --quiet --root /opt/deny {DENY}; '
                  'CARGO_HOME=/usr/local/cargo /opt/deny/bin/cargo-deny --log-level warn check')
        argv = [podman, 'run', '--rm', '-v', f'{ROOT}:/src:ro', '-w', '/src',
                '-v', 'ab-cargo-registry:/usr/local/cargo/registry', '-v', 'ab-deny:/opt/deny',
                '-e', 'CARGO_TARGET_DIR=/opt/deny/target', IMAGE, 'sh', '-c', script]
        result = subprocess.run(argv, capture_output=True, timeout=3600, check=False)
        (out / 'deny.stdout').write_bytes(result.stdout)
        (out / 'deny.stderr').write_bytes(result.stderr)
        report.update(argv=argv, returncode=result.returncode,
                      stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),
                      stderr_sha256=hashlib.sha256(result.stderr).hexdigest())
        if result.returncode == 0:
            report.update(status='PASS', reason='advisories, licenses, bans and sources ok')
            code = 0
        else:
            report.update(status='FAIL', reason='cargo-deny reported problems; see deny.stderr')
            code = 1
        return code
    finally:
        report['exit_code'] = code
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(f"{report['status']}: {report.get('reason', '')}")
        print(f'Report: {out / "result.json"}')


if __name__ == '__main__':
    sys.exit(main())
