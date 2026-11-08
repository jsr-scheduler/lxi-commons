#!/usr/bin/env python3
"""Ejecuta controles Rust. Un resultado limpio NO prueba ausencia de pánicos."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

LINTS = ('unsafe_code', 'unused_must_use', 'clippy::unwrap_used',
         'clippy::expect_used', 'clippy::panic', 'clippy::todo',
         'clippy::unimplemented', 'clippy::unreachable', 'clippy::indexing_slicing',
         'clippy::string_slice', 'clippy::arithmetic_side_effects',
         'clippy::as_conversions', 'clippy::dbg_macro')

def commands(cargo, manifest):
    prefix = [cargo]
    common = ['--manifest-path', str(manifest)]
    # Real-PG cases share a fixture lease; concurrency is exercised inside
    # coordinated cases, without queueing unrelated cases past that deadline.
    test_options = ['--', '--test-threads=1'] if manifest.parent.name == 'drca' else []
    return [
        prefix + ['fmt'] + common + ['--all', '--', '--check'],
        prefix + ['clippy'] + common + ['--locked', '--workspace', '--all-targets',
            '--release', '--', '-Dwarnings', '-Dunknown_lints'] + ['-F' + lint for lint in LINTS],
        prefix + ['test'] + common + ['--locked'] + test_options,
        prefix + ['test'] + common + ['--locked', '--release'] + test_options,
        prefix + ['build'] + common + ['--locked', '--release'],
    ]

def run_checks(root, manifest, logdir, timeout=600):
    report = {'schema': 1, 'status': 'NOT_RUN',
              'scope': 'Formato, lints y tests del workspace seleccionado; sin prueba formal.',
              'panic_proof': 'NOT_DEMONSTRATED', 'manifest': str(manifest),
              'manifest_sha256': hashlib.sha256(manifest.read_bytes()).hexdigest(),
              'steps': []}
    cargo = shutil.which('cargo')
    if not cargo:
        report['reason'] = 'cargo no disponible; ejecutar en host Rust o builder Linux.'
        return report, 2
    lock = manifest.parent / 'Cargo.lock'
    if not lock.is_file():
        report['reason'] = 'Falta Cargo.lock junto al manifiesto. Prepararlo explícitamente sin omitir --locked.'
        return report, 2
    report['lock_sha256'] = hashlib.sha256(lock.read_bytes()).hexdigest()
    env = os.environ.copy()
    env['CARGO_TERM_COLOR'] = 'never'
    key = hashlib.sha256(str(manifest.relative_to(root)).encode()).hexdigest()[:12]
    env['CARGO_TARGET_DIR'] = str(root / 'build/rust-policy/targets' / sys.platform / key)
    report['target_dir'] = env['CARGO_TARGET_DIR']
    for index, argv in enumerate(commands(cargo, manifest), start=1):
        record = {'argv': argv}
        report['steps'].append(record)
        stdout = logdir / f'{index:02d}.stdout.txt'
        stderr = logdir / f'{index:02d}.stderr.txt'
        record.update(stdout=str(stdout), stderr=str(stderr))
        try:
            with stdout.open('w', encoding='utf-8') as out, stderr.open('w', encoding='utf-8') as err:
                proc = subprocess.run(argv, cwd=manifest.parent, env=env, stdout=out,
                                      stderr=err, timeout=timeout, check=False)
            record['returncode'] = proc.returncode
        except subprocess.TimeoutExpired:
            record['error'] = 'TIMEOUT'
            report.update(status='FAIL', reason=f'Tiempo agotado en paso {index}.')
            return report, 1
        except OSError as exc:
            record['error'] = str(exc)
            report.update(status='FAIL', reason=f'No se pudo ejecutar el paso {index}.')
            return report, 1
        if proc.returncode:
            report.update(status='FAIL', reason=f'Falló paso {index}; revisar logs completos.')
            return report, 1
    if hashlib.sha256(lock.read_bytes()).hexdigest() != report['lock_sha256']:
        report.update(status='FAIL', reason='Cargo.lock cambió durante los controles.')
        return report, 1
    report['status'] = 'CHECKS_PASS'
    report['reason'] = 'Controles ejecutados sin fallo. Ausencia de pánicos NO DEMOSTRADA.'
    return report, 0

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--project', type=Path, required=True)
    ap.add_argument('--manifest', type=Path, required=True,
                    help='Ruta de Cargo.toml relativa al proyecto, o absoluta dentro de él.')
    ap.add_argument('--timeout', type=int, default=600)
    ap.add_argument('--require-panic-proof', action='store_true',
                    help='Falla también cuando los checks pasan: este verificador no demuestra esa propiedad.')
    args = ap.parse_args()
    root = args.project.resolve()
    manifest = (root / args.manifest).resolve()
    if not manifest.is_relative_to(root) or not manifest.is_file() or manifest.name != 'Cargo.toml':
        ap.error('El manifiesto debe ser Cargo.toml existente dentro del proyecto.')
    if args.timeout <= 0:
        ap.error('--timeout debe ser positivo.')
    logdir = root / 'build/rust-policy/runs' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    if not logdir.resolve().is_relative_to(root):
        ap.error('La ruta de logs sale del proyecto mediante un enlace simbólico.')
    logdir.mkdir(parents=True)
    report, code = run_checks(root, manifest, logdir, args.timeout)
    if args.require_panic_proof and code == 0:
        report['status'] = 'NOT_DEMONSTRATED'
        report['reason'] = 'Prueba de ausencia de pánicos requerida y no disponible.'
        code = 3
    report['exit_code'] = code
    dest = logdir / 'result.json'
    dest.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(report['status'] + ': ' + report['reason'])
    print('Informe: ' + str(dest))
    return code

if __name__ == '__main__':
    sys.exit(main())
