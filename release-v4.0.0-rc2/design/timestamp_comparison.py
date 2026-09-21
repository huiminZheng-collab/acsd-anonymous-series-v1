"""Offline real-receipt costs; separate from network service performance."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import tsa
import time_evidence

FIXTURE = ROOT / 'design' / 'rfc3161-approval-set-fixture'
PIN = '32e841a95cc1164101ffde41298ef2fc75c1c4372ef095e88a6bbd47dfb191fc'


def worker(recipe):
    if recipe == 'acsd-binding-plus-receipt':
        result = time_evidence.verify(ROOT / 'demo', FIXTURE, PIN,
                                      external_authority=True)
        assert result['subject_kind'] == 'approval-set'
    else:
        request = tsa.parse_tsq((FIXTURE / 'request.tsq').read_bytes())
        tsa.verify_tsr((FIXTURE / 'response.tsr').read_bytes(), request['imprint'],
                       trusted_cert_der=(FIXTURE / 'tsa-cert.der').read_bytes(),
                       trusted_fingerprint=PIN, expected_nonce=request['nonce'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', choices=['receipt-only', 'acsd-binding-plus-receipt'])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.worker:
        worker(args.worker)
        return
    if not args.output:
        parser.error('--output required')
    rows = []
    for rep in range(-1, 5):
        recipes = ['receipt-only', 'acsd-binding-plus-receipt']
        if rep % 2:
            recipes.reverse()
        for recipe in recipes:
            command = [sys.executable, str(Path(__file__).resolve()), '--worker', recipe]
            start = time.perf_counter()
            result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=120)
            elapsed = (time.perf_counter() - start) * 1000
            assert result.returncode == 0, result.stderr.decode('utf-8', 'replace')
            rows.append({'recipe': recipe, 'repetition': rep, 'warmup': rep == -1,
                         'ms': elapsed,
                         'command': ['<PYTHON>', 'design/timestamp_comparison.py',
                                     '--worker', recipe],
                         'returncode': result.returncode})
    check = subprocess.run([sys.executable, '-m', 'unittest', '-v',
                            'test_time_evidence', 'test_tsa_security', 'test_approval_set'],
                           cwd=ROOT, capture_output=True, timeout=180)
    assert check.returncode == 0, check.stderr.decode('utf-8', 'replace')
    report = {'scope': 'offline real RFC3161 receipt; same parser and signer pin; process startup included',
              'network_requests': 0, 'samples': rows, 'summary': {},
              'receipt_bytes': (FIXTURE / 'response.tsr').stat().st_size,
              'fixture_hashes': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in FIXTURE.iterdir() if p.is_file()},
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'security_check_stdout': check.stdout.decode('utf-8', 'replace'),
              'security_check_stderr': check.stderr.decode('utf-8', 'replace')}
    for recipe in recipes:
        values = [r['ms'] for r in rows if r['recipe'] == recipe and not r['warmup']]
        report['summary'][recipe] = {'median_ms': statistics.median(values),
                                    'min_ms': min(values), 'max_ms': max(values),
                                    'stdev_ms': statistics.stdev(values)}
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
    print(json.dumps(report['summary']))


if __name__ == '__main__':
    main()
