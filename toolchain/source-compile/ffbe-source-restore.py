"""Restore the exact source-only candidate in a fresh lab directory. Never import its modules."""
import base64
import hashlib
import json
import pathlib
import py_compile
import re
import sys
import urllib.request

PINS = {
    ('HmoobGod/FFBE-Custom', '1a36586e9a06b362df4eff9e54a08ca2a13b2330'),
    ('Elvlin/exvius-offline', '65da3ca6b7924774c6c22dfbe397157c4a8966c4'),
    ('Elvlin/exvius-offline', '8bcede33b4af67ad245e30d9053f2b4aef6923c6'),
}
CHECKPOINT = '8e96f0952ffd5b2945d456dac334a81d1f8deced7702b84039ca81b4d80ee420'
EXTENSIONS = {'.py', '.js', '.java', '.json', '.tsv', '.gradle', '.xml'}

def digest(b):
    return hashlib.sha256(b).hexdigest()

def verify(b, row):
    if len(b) != row['bytes'] or digest(b) != row['sha256'] or hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest() != row['git_blob']:
        raise ValueError('Source identity mismatch: '+row.get('path', row['git_blob']))

def fetch(path, pin, identity):
    if (pin['repo'], pin['ref']) not in PINS:
        raise ValueError('Unapproved public pin')
    url = 'https://raw.githubusercontent.com/'+pin['repo']+'/'+pin['ref']+'/'+path
    with urllib.request.urlopen(url, timeout=120) as response:
        if response.geturl() != url:
            raise ValueError('Unexpected public source redirect')
        data = response.read(identity['bytes']+1)
    verify(data, identity)
    return data

def restore(row, getter=fetch):
    if 'public' in row:
        data = getter(row['path'], row['public'], row)
    elif 'public_base' in row:
        base = row['public_base']
        lines = getter(row['path'], base, base).splitlines(keepends=True)
        last = 0
        for i,j,b in row['line_edits']:
            if not 0 <= last <= i <= j <= len(lines):
                raise ValueError('Invalid candidate edits')
            last = j
            base64.b64decode(b, validate=True)
        for i,j,b in reversed(row['line_edits']):
            lines[i:j] = [base64.b64decode(b, validate=True)]
        data = b''.join(lines)
    else:
        if row['path'] != 'source/memorial/android/src/main/java/com/exvius/local/BootstrapAdmissionGate.java':
            raise ValueError('Unexpected new authored source')
        data = base64.b64decode(row['new_authored_source'], validate=True)
    verify(data, row)
    return data

def load_manifest(path):
    m = json.loads(path.read_bytes())
    if m['schema'] != 1 or m['checkpoint_sha256'] != CHECKPOINT or m['pipeline'] != {'PIPELINE':58,'PIPELINE_EDGES':26} or m['real_runtime_approval'] is not False or m['automatic_installer_approval'] is not False:
        raise ValueError('Checkpoint metadata mismatch')
    rows = m['files']
    if len(rows) != 107 or sum(r['bytes'] for r in rows) != 101110031:
        raise ValueError('Unexpected source set')
    paths = set()
    for r in rows:
        p = pathlib.PurePosixPath(r['path'])
        if str(p) != r['path'] or p.parts[0] != 'source' or '..' in p.parts or p.suffix not in EXTENSIONS or not re.fullmatch(r'[A-Za-z0-9_./-]+', str(p)) or str(p).lower() in paths or not 0 < r['bytes'] < 90000000:
            raise ValueError('Unsafe or unexpected source path')
        paths.add(str(p).lower())
    return rows

def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ('restore','compile','verify'):
        raise SystemExit('Expected action, manifest, isolated source directory')
    action, manifest, target = sys.argv[1], pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
    rows = load_manifest(manifest)
    if action == 'restore':
        target.mkdir(exist_ok=False)
        for row in rows:
            out = target / row['path']
            data = restore(row)
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open('xb') as f:
                f.write(data)
        print('Verified 107/107 exact source files (96 direct public, 11 candidates)')
    for row in rows:
        path = target / row['path']
        if path.is_symlink():
            raise ValueError('Unexpected link')
        verify(path.read_bytes(), row)
    if action == 'compile':
        if sys.version_info[:3] != (3,10,11):
            raise ValueError('Expected target candidate CPython 3.10.11')
        outdir = target.parent / 'isolated-pyc'
        outdir.mkdir(exist_ok=False)
        files = [r['path'] for r in rows if r['path'].endswith('.py')]
        if len(files) != 49:
            raise ValueError('Unexpected Python source count')
        for n in files:
            dest = outdir / (n+'c')
            dest.parent.mkdir(parents=True, exist_ok=True)
            py_compile.compile(str(target/n), cfile=str(dest), dfile=n, doraise=True, invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH)
        print('CPython 3.10.11: 49/49 real source modules compiled, none imported')
    print(json.dumps({'action':action,'source_files':107,'pipeline':{'PIPELINE':58,'PIPELINE_EDGES':26},'real_runtime_approval':False,'automatic_installer_approval':False}))

if __name__ == '__main__':
    main()
