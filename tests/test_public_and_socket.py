"""Tests for the public landing-page API and Socket.IO authentication."""

import hashlib
import json

import pytest
from flask import Flask

from src.dashboard.routes import api_public


@pytest.fixture
def public_client(tmp_path):
    app = Flask(__name__)
    app.register_blueprint(api_public.init_public_routes('1.2.0', str(tmp_path)))
    return app.test_client(), tmp_path


def write_release(folder, content=b'fake build bytes', **overrides):
    (folder / 'SecureX-1.2.0-win64.zip').write_bytes(content)
    manifest = {
        'product': 'SecureX Threat Advisor', 'version': '1.2.0', 'status': 'preview',
        'released_at': '2026-10-19', 'platform': 'Windows x64', 'file': 'SecureX-1.2.0-win64.zip',
        'size_bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest(), 'notes': ['First preview'],
    }
    manifest.update(overrides)
    (folder / 'manifest.json').write_text(json.dumps(manifest))
    return manifest


def test_no_release_is_reported_honestly(public_client):
    client, _ = public_client
    body = client.get('/api/public/info').get_json()
    assert body['data'] == {'app_version': '1.2.0', 'release': None}
    assert client.get('/download/SecureX-1.2.0-win64.zip').status_code == 404


def test_verified_release_is_downloadable(public_client):
    client, folder = public_client
    write_release(folder)
    release = client.get('/api/public/info').get_json()['data']['release']
    assert release['download_url'] == '/download/SecureX-1.2.0-win64.zip'
    response = client.get(release['download_url'])
    assert response.status_code == 200 and response.data == b'fake build bytes'
    assert 'attachment' in response.headers['Content-Disposition']


def test_tampered_release_is_withdrawn(public_client):
    client, folder = public_client
    write_release(folder)
    (folder / 'SecureX-1.2.0-win64.zip').write_bytes(b'replaced by someone else')
    assert client.get('/api/public/info').get_json()['data']['release'] is None
    assert client.get('/download/SecureX-1.2.0-win64.zip').status_code == 404


def test_only_the_manifest_file_can_be_downloaded(public_client):
    client, folder = public_client
    write_release(folder)
    (folder / 'secret.txt').write_text('not for download')
    assert client.get('/download/manifest.json').status_code == 404
    assert client.get('/download/secret.txt').status_code == 404
    assert client.get('/download/..%2F..%2Fsrc%2Fauth.py').status_code == 404


def test_manifest_with_unsafe_filename_is_rejected(public_client):
    client, folder = public_client
    write_release(folder, file='../outside.zip')
    assert client.get('/api/public/info').get_json()['data']['release'] is None


def test_socket_requires_login():
    import src.dashboard.app as app_module
    app_module.app.config['TESTING'] = True

    anonymous = app_module.socketio.test_client(app_module.app, flask_test_client=app_module.app.test_client())
    assert not anonymous.is_connected()

    http_client = app_module.app.test_client()
    with http_client.session_transaction() as sess:
        sess['username'] = 'alice'
    signed_in = app_module.socketio.test_client(app_module.app, flask_test_client=http_client)
    assert signed_in.is_connected()
    assert signed_in.get_received()[0]['name'] == 'connected'
    signed_in.disconnect()


def test_release_zip_excludes_secrets_and_user_data(tmp_path):
    import subprocess
    import sys
    import zipfile

    build = tmp_path / 'build'
    (build / '_internal').mkdir(parents=True)
    (build / 'SecureX Threat Advisor.exe').write_bytes(b'exe')
    (build / '_internal' / 'lib.dll').write_bytes(b'dll')
    (build / '.env').write_text('SECUREX_SMTP_PASSWORD=secret\n')
    (build / 'data' / 'db').mkdir(parents=True)
    (build / 'data' / 'db' / 'threats.db').write_bytes(b'db')
    out = tmp_path / 'releases'

    script = __import__('os').path.join('scripts', 'build_release.py')
    result = subprocess.run([sys.executable, script, '--version', '9.9.9', '--skip-tests',
                             '--build-dir', str(build), '--out', str(out)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    names = zipfile.ZipFile(out / 'SecureX-9.9.9-win64.zip').namelist()
    assert 'SecureX Threat Advisor/SecureX Threat Advisor.exe' in names
    assert 'SecureX Threat Advisor/_internal/lib.dll' in names
    assert not any('.env' in name or '/data/' in name for name in names)
    manifest = json.loads((out / 'manifest.json').read_text())
    assert manifest['status'] == 'preview' and manifest['tests_run'] is False
