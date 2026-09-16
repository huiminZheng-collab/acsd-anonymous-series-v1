#!/usr/bin/env python3
"""Reproduce COMPARISON-PROTOCOL.md; outputs contain synthetic data only."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]


def detached_worker(operation, paper, bundle, keys):
    """Independent minimal baseline; trust comes from caller-pinned keys."""
    if operation == 'create':
        bundle.mkdir()
        shutil.copyfile(paper, bundle / 'paper.bin')
        content = paper.read_bytes()
        for i, key in enumerate(keys):
            private = ser.load_pem_private_key(key.read_bytes(), password=None)
            (bundle / f'{i}.sig').write_bytes(private.sign(content))
            (bundle / f'{i}.pub').write_bytes(private.public_key().public_bytes(
                ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))
    else:
        for i, key in enumerate(keys):
            public = ser.load_pem_public_key(key.read_bytes())
            public.verify((bundle / f'{i}.sig').read_bytes(),
                          (bundle / 'paper.bin').read_bytes())


class Experiment:
    def __init__(self, work, gpg):
        self.work, self.gpg, self.log = work, gpg, []

    def run(self, command, ok=True):
        start = time.perf_counter()
        result = subprocess.run(list(map(str, command)), cwd=ROOT,
                                capture_output=True, timeout=180)
        elapsed = (time.perf_counter() - start) * 1000
        self.log.append({'command': [self.public_arg(x) for x in command],
                         'elapsed_ms': elapsed, 'returncode': result.returncode})
        if ok and result.returncode:
            raise RuntimeError(result.stderr.decode('utf-8', 'replace') +
                               result.stdout.decode('utf-8', 'replace'))
        return result

    def public_arg(self, value):
        """Remove host-specific executable and workspace paths from reports."""
        text = str(value)
        replacements = (
            (str(self.work), '<WORK>'),
            (str(self.work).replace('\\', '/'), '<WORK>'),
            ('/' + str(self.work)[0].lower() + str(self.work)[2:].replace('\\', '/'),
             '<WORK>'),
            (str(ROOT), '<ROOT>'),
            (str(ROOT).replace('\\', '/'), '<ROOT>'),
            (str(Path(sys.executable)), '<PYTHON>'),
            (str(Path(self.gpg)), '<GPG>'),
        )
        for private, public in replacements:
            text = text.replace(private, public)
        return text

    def acsd(self, *args):
        return self.run([sys.executable, ROOT / 'acsd.py', *args, '--json'])

    def gp(self, home, *args, ok=True):
        def path_arg(value):
            value = str(value)
            if '/git/usr/bin/' in self.gpg.replace('\\', '/').lower() and len(value) > 2 and value[1] == ':':
                return '/' + value[0].lower() + value[2:].replace('\\', '/')
            return value
        return self.run([self.gpg, '--homedir', path_arg(home), '--batch', '--no-tty',
                         *map(path_arg, args)], ok=ok)

    def gverify(self, home, signature, paper, fingerprint, ok=True):
        result = self.gp(home, '--status-fd', '1', '--verify', signature, paper,
                         ok=False)
        valid = (result.returncode == 0 and
                 f'[GNUPG:] VALIDSIG {fingerprint} '.encode() in result.stdout)
        if ok and not valid:
            raise AssertionError('GPG signature or required fingerprint mismatch')
        return valid

    def setup(self):
        self.author = self.work / 'gpg-author'
        self.reader = self.work / 'gpg-reader'
        self.author.mkdir()
        self.reader.mkdir()
        self.fingerprints, self.private, self.public, self.acsd_keys = [], [], [], []
        for i in range(4):
            self.gp(self.author, '--pinentry-mode', 'loopback', '--passphrase', '',
                    '--quick-generate-key', f'Synthetic benchmark author {i}',
                    'ed25519', 'sign', '0')
        listing = self.gp(self.author, '--with-colons', '--list-keys').stdout.decode()
        self.fingerprints = [line.split(':')[9] for line in listing.splitlines()
                             if line.startswith('fpr:')]
        assert len(self.fingerprints) == 4
        exported = self.work / 'public.gpg'
        self.gp(self.author, '--output', exported, '--export')
        self.gp(self.reader, '--import', exported)
        for i in range(3):
            key = Ed25519PrivateKey.generate()
            private, public = self.work / f'{i}.pem', self.work / f'{i}.pub'
            private.write_bytes(key.private_bytes(ser.Encoding.PEM,
                                ser.PrivateFormat.PKCS8, ser.NoEncryption()))
            public.write_bytes(key.public_key().public_bytes(
                ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))
            self.private.append(private)
            self.public.append(public)
            data = json.loads(self.acsd('keygen', '--name', f'author{i}',
                              '--out-dir', self.work / 'keys').stdout)['data']
            self.acsd_keys.append(data['private_key'])

    def create(self, recipe, paper, bundle, authors):
        if recipe == 'acsd':
            flags = [v for k in self.acsd_keys[:authors] for v in ('--key', k)]
            self.acsd('release', paper, *flags, '--out', bundle)
        elif recipe == 'detached-ed25519':
            self.run([sys.executable, __file__, '--worker', 'create', paper,
                      bundle, *self.private[:authors]])
        else:
            bundle.mkdir()
            shutil.copyfile(paper, bundle / 'paper.bin')
            for i, fp in enumerate(self.fingerprints[:authors]):
                self.gp(self.author, '--local-user', fp, '--output', bundle / f'{i}.sig',
                        '--detach-sign', bundle / 'paper.bin')
                self.gp(self.author, '--output', bundle / f'{i}.pub', '--export', fp)

    def verify(self, recipe, bundle, authors):
        if recipe == 'acsd':
            self.acsd('verify', bundle)
        elif recipe == 'detached-ed25519':
            self.run([sys.executable, __file__, '--worker', 'verify',
                      bundle / 'paper.bin', bundle, *self.public[:authors]])
        else:
            for i, fp in enumerate(self.fingerprints[:authors]):
                self.gverify(self.reader, bundle / f'{i}.sig', bundle / 'paper.bin', fp)

    def security(self):
        reports = {}
        for name in ('adjacent_baseline', 'submission_lifecycle',
                     'multi_author_unblinding', 'cross_paper_isolation'):
            reports[name] = json.loads(self.run([
                sys.executable, ROOT / 'design' / f'{name}_runner.py']).stdout)
        paper = self.work / 'security.bin'
        paper.write_bytes(b'Synthetic parent manuscript\n')
        package = self.work / 'gpg-security'
        self.create('gpg', paper, package, 3)
        self.verify('gpg', package, 3)
        changed = self.work / 'changed.bin'
        changed.write_bytes(paper.read_bytes() + b'changed')
        fp, attacker = self.fingerprints[0], self.fingerprints[3]
        assert not self.gverify(self.reader, package / '0.sig', changed, fp, ok=False)
        assert not self.gverify(self.reader, package / 'absent.sig', paper, fp, ok=False)
        attack_sig = self.work / 'attack.sig'
        self.gp(self.author, '--local-user', attacker, '--output', attack_sig,
                '--detach-sign', changed)
        assert self.gverify(self.reader, attack_sig, changed, attacker)
        assert not self.gverify(self.reader, attack_sig, changed, fp, ok=False)
        transition = self.work / 'transition.json'
        statement = {'schema': 'manual-transition/v1',
                     'parent': hashlib.sha256(paper.read_bytes()).hexdigest(),
                     'child': hashlib.sha256(changed.read_bytes()).hexdigest(),
                     'successor_fingerprint': attacker}
        transition.write_text(json.dumps(statement, sort_keys=True, separators=(',', ':')))
        sig = self.work / 'transition.sig'
        self.gp(self.author, '--local-user', fp, '--output', sig, '--detach-sign', transition)
        assert self.gverify(self.reader, sig, transition, fp)
        statement['child'] = hashlib.sha256(b'another child').hexdigest()
        replay = self.work / 'replay.json'
        replay.write_text(json.dumps(statement, sort_keys=True, separators=(',', ':')))
        assert not self.gverify(self.reader, sig, replay, fp, ok=False)
        reports['actual_gpg'] = {
            'three_signers': 'accepted', 'tampered_bytes': 'rejected',
            'missing_required_signature': 'rejected',
            'fresh_key_self_declared': 'valid signature; succession outside recipe',
            'fresh_key_pinned_predecessor': 'rejected',
            'manual_exact_transition': 'accepted', 'transition_replay': 'rejected'}
        return reports


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--worker':
        detached_worker(sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4]),
                        list(map(Path, sys.argv[5:])))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--gpg', default=shutil.which('gpg') or
                        r'C:\Program Files\Git\usr\bin\gpg.exe')
    parser.add_argument('--repetitions', type=int, default=5)
    args = parser.parse_args()
    if args.repetitions < 2:
        parser.error('at least two measured repetitions required')
    args.output.mkdir(parents=True, exist_ok=False)
    rng = random.Random(20260915)
    report = {'schema': 'acsd-comparative-evaluation/v1', 'environment': {
        'python': sys.version, 'platform': platform.platform(),
        'processor': platform.processor(), 'logical_cpus': os.cpu_count()},
        'protocol_sha256': hashlib.sha256((ROOT / 'design' /
                               'COMPARISON-PROTOCOL.md').read_bytes()).hexdigest(),
        'source_hashes': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in sorted(ROOT.glob('*.py'))},
        'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'repetitions': args.repetitions, 'samples': [], 'summary': []}
    with tempfile.TemporaryDirectory(prefix='acsd-comparison-') as temporary:
        exp = Experiment(Path(temporary), args.gpg)
        gpg_version = exp.run([args.gpg, '--version']).stdout.decode().splitlines()
        report['environment']['gpg'] = '\n'.join(gpg_version[:2])
        exp.setup()
        for size in (65536, 1048576, 8388608):
            paper = exp.work / f'paper-{size}.bin'
            block = b'ACSD synthetic manuscript line.\n'
            paper.write_bytes((block * (size // len(block) + 1))[:size])
            assert paper.stat().st_size == size
            for authors in (1, 3):
                for rep in range(-1, args.repetitions):
                    recipes = ['acsd', 'detached-ed25519', 'gpg']
                    rng.shuffle(recipes)
                    for recipe in recipes:
                        bundle = exp.work / f'{size}-{authors}-{rep}-{recipe}'
                        row = {'bytes': size, 'authors': authors, 'repetition': rep,
                               'warmup': rep == -1, 'recipe': recipe}
                        for op in ('create', 'verify'):
                            before = len(exp.log)
                            start = time.perf_counter()
                            if op == 'create':
                                exp.create(recipe, paper, bundle, authors)
                            else:
                                exp.verify(recipe, bundle, authors)
                            row[op + '_ms'] = (time.perf_counter() - start) * 1000
                            row[op + '_commands'] = len(exp.log) - before
                        files = [p for p in bundle.rglob('*') if p.is_file()]
                        row.update(artifact_files=len(files),
                                   artifact_bytes=sum(p.stat().st_size for p in files))
                        report['samples'].append(row)
                print(f'completed {size} bytes / {authors} authors', flush=True)
        for recipe in ('acsd', 'detached-ed25519', 'gpg'):
            for size in (65536, 1048576, 8388608):
                for authors in (1, 3):
                    rows = [r for r in report['samples'] if not r['warmup'] and
                            (r['recipe'], r['bytes'], r['authors']) == (recipe, size, authors)]
                    summary = {'recipe': recipe, 'bytes': size, 'authors': authors}
                    for metric in ('create_ms', 'verify_ms', 'artifact_bytes'):
                        values = [r[metric] for r in rows]
                        summary[metric] = {'median': statistics.median(values),
                                           'min': min(values), 'max': max(values),
                                           'stdev': statistics.stdev(values)}
                    report['summary'].append(summary)
        report['security'] = exp.security()
        report['commands'] = exp.log
    (args.output / 'results.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(f'PASS: {len(report["samples"])} samples; security assertions passed')


if __name__ == '__main__':
    main()
