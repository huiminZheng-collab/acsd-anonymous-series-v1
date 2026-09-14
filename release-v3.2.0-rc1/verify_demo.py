import pathlib

from package_manifest import verify_manifest

def verify_demo(root='demo'):
    return verify_manifest(pathlib.Path(root))

if __name__ == '__main__': print({'entries': verify_demo(), 'status': 'VALID'})
