import hashlib, pathlib, re

def verify_demo(root='demo'):
    root=pathlib.Path(root); manifest=(root/'MANIFEST.sha256').read_text(encoding='utf-8').strip().splitlines()
    expected={}
    for line in manifest:
        digest,name=line.split('  ',1)
        if not re.fullmatch(r'[0-9a-f]{64}',digest) or name in expected: raise ValueError('MANIFEST_INVALID')
        expected[name]=digest
    actual=sorted(p.name for p in root.iterdir() if p.is_file() and p.name != 'MANIFEST.sha256')
    if sorted(expected) != actual: raise ValueError('MANIFEST_SET_MISMATCH')
    for name,want in expected.items():
        if hashlib.sha256((root/name).read_bytes()).hexdigest() != want: raise ValueError('MANIFEST_HASH_MISMATCH')
    return len(actual)

if __name__ == '__main__': print({'entries': verify_demo(), 'status': 'VALID'})
