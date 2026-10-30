"""Public (no login) routes for the landing page.

Release metadata comes from releases/manifest.json, written by
scripts/build_release.py. A download is offered only when the manifest is
present and the file on disk still matches the SHA-256 recorded in it, so the
landing page never shows a broken or substituted download.
"""

import hashlib
import json
import logging
import os
import re

from flask import Blueprint, abort, jsonify, send_from_directory

logger = logging.getLogger('securex')

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
# SECUREX_RELEASES_DIR lets the packaged app (whose PROJECT_ROOT is its
# read-only _internal folder) serve releases from elsewhere.
RELEASES_DIR = os.environ.get('SECUREX_RELEASES_DIR') or os.path.join(PROJECT_ROOT, 'releases')
MANIFEST_FIELDS = ('version', 'status', 'released_at', 'platform', 'file', 'size_bytes', 'sha256')
SAFE_FILENAME = re.compile(r'^[A-Za-z0-9._-]+$')

_hash_cache = {}


def _sha256(path):
    stat = os.stat(path)
    key = (path, stat.st_size, stat.st_mtime)
    if key not in _hash_cache:
        digest = hashlib.sha256()
        with open(path, 'rb') as handle:
            for block in iter(lambda: handle.read(1 << 20), b''):
                digest.update(block)
        _hash_cache.clear()
        _hash_cache[key] = digest.hexdigest()
    return _hash_cache[key]


def load_verified_release(releases_dir=None):
    """Return the manifest if its file exists and matches its checksum, else None."""
    releases_dir = releases_dir or RELEASES_DIR
    manifest_path = os.path.join(releases_dir, 'manifest.json')
    if not os.path.isfile(manifest_path):
        return None
    try:
        with open(manifest_path, encoding='utf-8') as handle:
            manifest = json.load(handle)
    except (OSError, ValueError) as error:
        logger.warning('Invalid release manifest: %s', error)
        return None
    if not all(manifest.get(field) for field in MANIFEST_FIELDS):
        logger.warning('Release manifest is missing required fields')
        return None
    filename = manifest['file']
    path = os.path.join(releases_dir, filename)
    if not SAFE_FILENAME.match(filename) or not os.path.isfile(path):
        logger.warning('Release file %r is missing', filename)
        return None
    if _sha256(path) != manifest['sha256'].lower():
        logger.warning('Release file %r does not match its manifest checksum', filename)
        return None
    return manifest


def init_public_routes(app_version, releases_dir=None):
    # A fresh blueprint per call, so the app module can be re-imported (tests).
    public_bp = Blueprint('public', __name__)

    @public_bp.route('/api/public/info', methods=['GET'])
    def public_info():
        release = load_verified_release(releases_dir)
        if release:
            release = dict(release, download_url=f"/download/{release['file']}")
        return jsonify({'success': True, 'data': {'app_version': app_version, 'release': release}})

    @public_bp.route('/download/<filename>', methods=['GET'])
    def download(filename):
        release = load_verified_release(releases_dir)
        if not release or filename != release['file']:
            abort(404)
        return send_from_directory(releases_dir or RELEASES_DIR, filename, as_attachment=True)

    return public_bp
