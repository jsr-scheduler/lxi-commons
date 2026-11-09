#!/usr/bin/env python3
"""lxi-commons PG16 integration tests in podman. PASS=0 FAIL=1 NOT_RUN=2 DEV_ONLY=4.

Creates, uses and removes only podman objects named lxi-it-<run>*. Secrets go
to 0600 env files under build/, never to argv or logs.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
# docker.io/library/postgres:16-bookworm, arm64, pulled 2026-11-07.
# Both from one postgres:16-bookworm index: arm64 is the acceptance image; amd64 serves
# only the GitHub CI (--target host), whose results are DEV_ONLY, never acceptance.
PG_IMAGES = {
    'arm64': 'docker.io/library/postgres@sha256:fb4a48f09f19618d307deb5d153a0b11768d37d5c3592ad0c63737dbe52c78ce',
    'amd64': 'docker.io/library/postgres@sha256:5983db9a9c6ad225a48a46cfe2e03e6680b1826662befd0465eb05b34cb1c64e',
}
HOST_ARCH = {'arm64': 'arm64', 'aarch64': 'arm64', 'x86_64': 'amd64', 'amd64': 'amd64'}.get(
    platform.machine().lower(), 'unknown')
PG_IMAGE = PG_IMAGES.get(HOST_ARCH, PG_IMAGES['arm64'])
PG_TAG = 'docker.io/library/postgres:16-bookworm'
# containers/Containerfile.builder (rust:1.90-slim-bookworm arm64 + rustfmt/clippy).
BUILDER = 'localhost/lxi-builder:1.90-pam'
# NOT_RUN markers a target may legitimately print (see the plan, Task 5).
ALLOWED_NOT_RUN = {'macos': {'the_unix_socket_peer_must_be_the_expected_uid'},
                   # host: PG in podman, cargo on the host (macOS, or the GitHub CI).
                   'host': {'the_unix_socket_peer_must_be_the_expected_uid'},
                   'linux': set()}
# uid of the postgres user in the pinned image (owner of its Unix socket).
PG_UID = '999'
HBA = """local all postgres trust
local all all scram-sha-256
host all all 0.0.0.0/0 scram-sha-256
host all all ::/0 scram-sha-256
hostssl all all 0.0.0.0/0 scram-sha-256
"""


class Runner:
    def __init__(self, out, run_id):
        self.out = out
        self.run_id = run_id
        self.steps = []

    def run(self, name, argv, expect=0, stdin=None, env=None, timeout=900):
        index = len(self.steps) + 1
        stdout = self.out / f'{index:02d}-{name}.stdout'
        stderr = self.out / f'{index:02d}-{name}.stderr'
        try:
            result = subprocess.run(argv, input=stdin, capture_output=True, env=env,
                                    timeout=timeout, cwd=ROOT, check=False)
            code, out_bytes, err_bytes = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as exc:
            code, out_bytes, err_bytes = 'TIMEOUT', exc.stdout or b'', exc.stderr or b''
        stdout.write_bytes(out_bytes)
        stderr.write_bytes(err_bytes)
        self.steps.append(dict(name=name, argv=[str(a) for a in argv], returncode=code,
                               stdout=str(stdout.relative_to(self.out)),
                               stderr=str(stderr.relative_to(self.out)),
                               stdout_sha256=hashlib.sha256(out_bytes).hexdigest(),
                               stderr_sha256=hashlib.sha256(err_bytes).hexdigest()))
        if expect is not None and code != expect:
            raise StepFailed(f'{name} returned {code}')
        return out_bytes.decode(errors='replace')


class StepFailed(Exception):
    pass


def private_write(path, text, mode=0o600):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, 'w') as stream:
        stream.write(text)


def certificates(r, private, pg_name):
    """A CA, a server certificate for 127.0.0.1 and pg_name, and an unrelated CA."""
    ssl = shutil.which('openssl')
    if not ssl:
        raise NotRun('openssl not found')
    ca_ext = private / 'ca.cnf'
    private_write(ca_ext, '[req]\ndistinguished_name=dn\n[dn]\n[v3_ca]\n'
                  'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n'
                  'subjectKeyIdentifier=hash\n')
    server_ext = private / 'server.cnf'
    private_write(server_ext, f'basicConstraints=critical,CA:FALSE\n'
                  f'keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n'
                  f'subjectAltName=IP:127.0.0.1,DNS:{pg_name}\n')
    for ca in ['ca', 'wrong-ca']:
        r.run(f'{ca}-key', [ssl, 'ecparam', '-name', 'prime256v1', '-genkey', '-noout',
                            '-out', private / f'{ca}.key'])
        r.run(f'{ca}-cert', [ssl, 'req', '-x509', '-new', '-key', private / f'{ca}.key',
                             '-subj', f'/CN=ab-it {ca}', '-days', '2', '-config', ca_ext,
                             '-extensions', 'v3_ca', '-out', private / f'{ca}.pem'])
    r.run('server-key', [ssl, 'ecparam', '-name', 'prime256v1', '-genkey', '-noout',
                         '-out', private / 'server.key'])
    r.run('server-csr', [ssl, 'req', '-new', '-key', private / 'server.key',
                         '-subj', '/CN=ab-it-server', '-config', ca_ext,
                         '-out', private / 'server.csr'])
    r.run('server-cert', [ssl, 'x509', '-req', '-in', private / 'server.csr',
                          '-CA', private / 'ca.pem', '-CAkey', private / 'ca.key',
                          '-CAcreateserial', '-days', '2', '-extfile', server_ext,
                          '-out', private / 'server.pem'])
    for name in ['ca.pem', 'wrong-ca.pem']:
        (private / name).chmod(0o644)


class NotRun(Exception):
    pass


def not_run_markers(text):
    # With --nocapture a marker may share the line with libtest's `test name ... `.
    return set(re.findall(r'NOT_RUN:([a-z0-9_]+)', text))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', choices=['macos', 'linux', 'host'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--pull', action='store_true', help='pull the pinned image if absent')
    parser.add_argument('--allow-dev', action='store_true',
                        help='report DEV_ONLY instead of FAIL for a non-16/non-arm64 PG')
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    run_id = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S') + '-' + secrets.token_hex(3)
    prefix = f'lxi-it-{run_id}'
    r = Runner(out, run_id)
    report = dict(schema=1, status='RUNNING', target=args.target, run_id=run_id,
                  started_utc=datetime.now(timezone.utc).isoformat(), image=PG_IMAGE,
                  host=dict(system=platform.system(), machine=platform.machine()),
                  panic_absence='NOT_DEMONSTRATED', not_run=[])
    code = 1
    created = dict(container=False, network=False, volumes=[], fresh=False)
    private = None
    podman = shutil.which('podman')
    try:
        if not podman:
            raise NotRun('podman not found')
        if args.target == 'macos' and platform.system() != 'Darwin':
            raise NotRun('macos target needs a Darwin host')
        r.run('image-exists', [podman, 'image', 'exists', PG_IMAGE], expect=None)
        if r.steps[-1]['returncode'] != 0:
            if not args.pull:
                raise NotRun(f'{PG_TAG} not present: rerun with --pull')
            r.run('image-pull', [podman, 'pull', '--arch', HOST_ARCH if args.target == 'host' else 'arm64', PG_IMAGE])
        arch = r.run('image-arch', [podman, 'image', 'inspect', PG_IMAGE,
                                    '--format', '{{.Architecture}}']).strip()
        report['image_architecture'] = arch
        if args.target == 'linux':
            r.run('builder-exists', [podman, 'image', 'exists', BUILDER], expect=None)
            if r.steps[-1]['returncode'] != 0:
                raise NotRun(f'{BUILDER} missing: podman build -t {BUILDER} '
                             '-f containers/Containerfile.builder containers')
            report['builder_image_id'] = r.run('builder-id', [
                podman, 'image', 'inspect', BUILDER, '--format', '{{.Id}}']).strip()

        private = ROOT / 'build/pg-it' / run_id / 'private'
        private.mkdir(parents=True, mode=0o700)
        pg_name = f'{prefix}-pg'
        certificates(r, private, pg_name)
        passwords = {k: secrets.token_hex(24) for k in ['super', 'eval', 'admin', 'audit', 'app']}
        private_write(private / 'pg_hba.conf', HBA)
        private_write(private / 'pg.env', f"POSTGRES_PASSWORD={passwords['super']}\n")

        network, conf, sock = f'{prefix}-net', f'{prefix}-conf', f'{prefix}-sock'
        r.run('network', [podman, 'network', 'create', network])
        created['network'] = network
        for volume in [conf, sock]:
            r.run(f'volume-{volume[-4:]}', [podman, 'volume', 'create', volume])
            created['volumes'].append(volume)
        r.run('stage-conf', [podman, 'run', '--rm', '--network=none', '-v', f'{private}:/src:ro',
                             '-v', f'{conf}:/conf', '--entrypoint', 'sh',
                             PG_IMAGE, '-c',
                             'cp /src/server.pem /src/server.key /src/pg_hba.conf /conf/ && '
                             'chown -R 999:999 /conf && chmod 0600 /conf/server.key'])
        r.run('pg-start', [podman, 'run', '-d', '--name', pg_name, '--network', network,
                           '-p', '127.0.0.1::5432', '--env-file', private / 'pg.env',
                           # The socket volume replaces /var/run/postgresql, which the image
                           # owns as postgres; podman copies that ownership on first mount.
                           '-e', 'POSTGRES_DB=ab', '-v', f'{conf}:/conf:ro',
                           '-v', f'{sock}:/var/run/postgresql',
                           PG_IMAGE, '-c', 'ssl=on', '-c', 'ssl_cert_file=/conf/server.pem',
                           '-c', 'ssl_key_file=/conf/server.key', '-c', 'hba_file=/conf/pg_hba.conf',
                           '-c', 'unix_socket_directories=/var/run/postgresql'])
        created['container'] = pg_name
        for attempt in range(120):
            ready = subprocess.run([podman, 'exec', pg_name, 'pg_isready', '-h', '127.0.0.1',
                                    '-U', 'postgres'], capture_output=True, check=False)
            if ready.returncode == 0:
                break
            time.sleep(0.5)
        else:
            r.run('pg-logs', [podman, 'logs', pg_name], expect=None)
            raise StepFailed('PostgreSQL did not become ready')
        psql = [podman, 'exec', '-i', pg_name, 'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1',
                '-U', 'postgres', '-h', '/var/run/postgresql', '-d', 'ab']
        version = r.run('server-version', [podman, 'exec', pg_name, 'psql', '-X', '-Atc',
                                           'SHOW server_version', '-U', 'postgres',
                                           '-h', '/var/run/postgresql', '-d', 'ab']).strip()
        report['server_version'] = version

        env_lines = {'LXI_IT_SUPER_PASSWORD': passwords['super']}
        if args.target in ('macos', 'host'):
            port = r.run('pg-port', [podman, 'port', pg_name, '5432/tcp']).strip().rsplit(':', 1)[-1]
            env_lines.update(LXI_IT_PG_PORT=port,
                             LXI_IT_CA_FILE=str(private / 'ca.pem'),
                             LXI_IT_WRONG_CA_FILE=str(private / 'wrong-ca.pem'))
        else:
            address = r.run('pg-ip', [podman, 'inspect', pg_name, '--format',
                                      '{{(index .NetworkSettings.Networks "' + network +
                                      '").IPAddress}}']).strip()
            env_lines.update(LXI_IT_PG_PORT='5432',
                             LXI_IT_CA_FILE='/private/ca.pem', LXI_IT_WRONG_CA_FILE='/private/wrong-ca.pem',
                             LXI_IT_PG_SOCKET_DIR='/sock', LXI_IT_PG_UID=PG_UID, LXI_IT_TLS_HOSTNAME=pg_name)
        report['pg_port'] = env_lines['LXI_IT_PG_PORT']
        env_file = private / 'tests.env'
        private_write(env_file, ''.join(f'{k}={v}\n' for k, v in env_lines.items()))

        phases = [('tests-debug', []), ('tests-release', ['--release'])]
        markers = set()
        for name, profile in phases:
            cargo = ['cargo', 'test', '--locked', *profile, '-p', 'lxi-pgclient', '--test', 'pg', '--',
                     '--ignored', '--test-threads=1', '--nocapture']
            if args.target in ('macos', 'host'):
                env = dict(os.environ, **env_lines, CARGO_TERM_COLOR='never',
                           CARGO_TARGET_DIR=str(ROOT / 'build/pg-it/targets/darwin'))
                text = r.run(name, cargo, env=env)
            else:
                target = ROOT / 'build/pg-it/targets/linux'
                target.mkdir(parents=True, exist_ok=True)
                registry = Path.home() / '.cargo/registry'
                text = r.run(name, [podman, 'run', '--rm', '--name', f'{prefix}-{name}',
                                    '--network', network, '--env-file', env_file,
                                    '-e', 'CARGO_TARGET_DIR=/target', '-e', 'CARGO_NET_OFFLINE=true',
                                    '-e', 'CARGO_TERM_COLOR=never',
                                    '-v', f'{ROOT}:/src:ro', '-v', f'{registry}:/usr/local/cargo/registry:ro',
                                    '-v', f'{target}:/target', '-v', f'{sock}:/sock',
                                    '-v', f'{private}:/private:ro', '-w', '/src', BUILDER, *cargo])
            markers |= not_run_markers(text)
        report['not_run'] = sorted(markers)
        unexpected = markers - ALLOWED_NOT_RUN[args.target]
        if unexpected:
            raise StepFailed(f'unexpected NOT_RUN on {args.target}: {sorted(unexpected)}')
        if not version.startswith('16.') or arch != 'arm64':
            if not args.allow_dev:
                raise StepFailed(f'PG {version}/{arch} is not acceptance evidence')
            report.update(status='DEV_ONLY', reason=f'PG {version}/{arch}')
            code = 4
        else:
            report.update(status='PASS', reason='all phases passed')
            code = 0
    except NotRun as exc:
        report.update(status='NOT_RUN', reason=str(exc))
        code = 2
    except StepFailed as exc:
        report.update(status='FAIL', reason=str(exc))
        code = 1
    finally:
        if podman:
            if created['fresh']:
                r.run('fresh-remove', [podman, 'rm', '-f', created['fresh']], expect=None)
            if created['container']:
                r.run('pg-logs', [podman, 'logs', created['container']], expect=None)
                r.run('pg-remove', [podman, 'rm', '-f', created['container']], expect=None)
            for volume in created['volumes']:
                r.run(f'remove-{volume[-4:]}', [podman, 'volume', 'rm', '-f', volume], expect=None)
            if created['network']:
                r.run('network-remove', [podman, 'network', 'rm', '-f', created['network']],
                      expect=None)
        if private is not None:
            # Passwords and keys exist only for this run.
            shutil.rmtree(private.parent, ignore_errors=True)
        report['steps'] = r.steps
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        report['exit_code'] = code
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(f"{report['status']}: {report.get('reason', '')}")
        print(f'Report: {out / "result.json"}')
    return code


if __name__ == '__main__':
    sys.exit(main())
