"""Package the PyInstaller desktop build and publish it to the landing page.

Steps:
  1. Run the test suite (skip with --skip-tests only for local experiments;
     such a build is always labelled "preview").
  2. Check that the PyInstaller output exists:
     dist/SecureX Threat Advisor/SecureX Threat Advisor.exe
  3. Zip it to releases/SecureX-<version>-win64.zip.
  4. Write releases/manifest.json with size, SHA-256, date and notes.

Build the executable first:
  pyinstaller desktop_app.spec --noconfirm

Then:
  python scripts/build_release.py --version 1.2.0 --notes "First preview build"

Use --status stable only after the build has been installed and tested on a
clean supported Windows machine. A checksum shows the file was not corrupted
or swapped on this server; it is not a code signature.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import zipfile
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_DIR = os.path.join(ROOT, 'dist', 'SecureX Threat Advisor')
EXE_NAME = 'SecureX Threat Advisor.exe'
RELEASES_DIR = os.path.join(ROOT, 'releases')
# Never ship local secrets or user data: .env holds SECRET_KEY and SMTP/AI
# credentials, data/ holds the database and logs created by running the app.
EXCLUDED_TOP_LEVEL = {'.env', 'data'}


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--version', required=True)
    parser.add_argument('--status', choices=['preview', 'stable'], default='preview')
    parser.add_argument('--notes', action='append', default=[], help='release note line (repeatable)')
    parser.add_argument('--skip-tests', action='store_true')
    parser.add_argument('--build-dir', default=BUILD_DIR)
    parser.add_argument('--out', default=RELEASES_DIR)
    args = parser.parse_args()

    if args.skip_tests:
        if args.status == 'stable':
            sys.exit('A stable release cannot skip the test suite.')
    else:
        env = dict(os.environ, FLASK_ENV='testing')
        if subprocess.run([sys.executable, '-m', 'pytest', '-q'], cwd=ROOT, env=env).returncode != 0:
            sys.exit('Tests failed; not publishing a release.')

    exe = os.path.join(args.build_dir, EXE_NAME)
    if not os.path.isfile(exe):
        sys.exit(f'Executable not found: {exe}\nRun: pyinstaller desktop_app.spec --noconfirm')

    os.makedirs(args.out, exist_ok=True)
    filename = f'SecureX-{args.version}-win64.zip'
    archive = os.path.join(args.out, filename)
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as zf:
        for folder, dirs, files in os.walk(args.build_dir):
            if os.path.abspath(folder) == os.path.abspath(args.build_dir):
                dirs[:] = [d for d in dirs if d not in EXCLUDED_TOP_LEVEL]
                files = [f for f in files if f not in EXCLUDED_TOP_LEVEL]
            for name in files:
                full = os.path.join(folder, name)
                zf.write(full, os.path.join('SecureX Threat Advisor', os.path.relpath(full, args.build_dir)))

    manifest = {
        'product': 'SecureX Threat Advisor',
        'version': args.version,
        'status': args.status,
        'released_at': datetime.now(timezone.utc).strftime('%Y-%m-%d'),
        'platform': 'Windows x64',
        'file': filename,
        'size_bytes': os.path.getsize(archive),
        'sha256': sha256(archive),
        'tests_run': not args.skip_tests,
        'notes': args.notes,
    }
    manifest_path = os.path.join(args.out, 'manifest.json')
    with open(manifest_path, 'w', encoding='utf-8') as handle:
        json.dump(manifest, handle, indent=2)
    print(json.dumps(manifest, indent=2))
    print(f'Wrote {archive}\nWrote {manifest_path}')


if __name__ == '__main__':
    main()
