#!/usr/bin/env python3
"""Source-only cloud pack inventory. No FFBE imports, execution, installation or extraction.

PUBLIC mode can only fetch the exact pinned 23 release ZIPs after explicit CLI +
environment authorization. LOCAL mode uses preexisting test packs without network.
The ZIP file entries are read and hashed as streams, never installed/extracted.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
import unicodedata
import urllib.parse
import urllib.request
import zipfile

SOURCE_REPO = 'Elvlin/exvius-offline'
SOURCE_COMMIT = '65da3ca6b7924774c6c22dfbe397157c4a8966c4'
SOURCE_BLOB = 'b79394fdf70c88a841d8600ea89d35fcc77b411c'
SCHEMA = 'ffbe_public_rev13_pack_entries_v1'
CHUNK = 1024 * 1024
MAX_PACK_BYTES = 2_147_483_647  # Same cap enforced in pinned Android downloader.
MAX_UNPACKED_BYTES = 4_000_000_000
MAX_MEMBERS = 100_000
MAX_TOTAL_MEMBERS = 250_000
ALLOWED_ARCHIVE_TYPES = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
ALLOWED_HOSTS = {'github.com', 'release-assets.githubusercontent.com',
                 'objects.githubusercontent.com', 'github-releases.githubusercontent.com',
                 'raw.githubusercontent.com'}
# Exact native destination roots permitted by pinned DataPack.java::destination().
# These are FILE roots; directory markers may also name their ancestors.
NATIVE_FILE_ROOTS = (
    'mst', 'localized_texts', 'common_lang', 'en', 'homeMarquee',
    'exvius/equipment-enhancement',
)

BRIDGE_PATHS = (
    ('MST_DIR', 'mst_decoded', 'dir'),
    ('TEXT_DIR', 'text_decoded', 'dir'),
    ('ART_ROOT', 'cpk_extract', 'dir'),
    ('CDN_ROOT', 'client/files', 'dir'),
    ('COMMUNITY_ART_ROOT', 'gacha_community/art', 'dir'),
    ('CDN_OVERLAY', 'overlay', 'dir'),
    ('VERSION_TABLE_XML', 'client/shared_prefs/gamedata.xml', 'file'),
)


class InventoryError(Exception):
    pass


def fail(message):
    raise InventoryError(message)


def safe_path(raw: str, *, directory: bool = False) -> str:
    """Validate a *file* destination or an explicit structural directory marker.

    Only the exact three file destination forms from pinned DataPack.java are
    permitted. Directory entries are structural only and never hashed as files.
    """
    if not isinstance(raw, str) or not raw or raw.startswith('/') or '\\' in raw:
        fail('Invalid ZIP entry name')
    if unicodedata.normalize('NFC', raw) != raw:
        fail('Non-NFC ZIP entry name')
    if raw.endswith('/'):
        if not directory:
            fail('Unexpected directory suffix')
        raw = raw[:-1]
    if not raw or '//' in raw:
        fail('Empty ZIP path segment')
    parts = raw.split('/')
    if any(p in ('.', '..', '') or ':' in p or any(ord(c) < 32 or ord(c) == 127 or
           unicodedata.category(c) == 'Cs' for c in p) for p in parts):
        fail('Unsafe ZIP entry component')
    if raw != PurePosixPath(raw).as_posix():
        fail('Noncanonical ZIP path')

    # Android's DataPack.java skips directory entries without invoking
    # destination(). Still reject anything outside an authenticated tree.
    if directory and raw in ('static', 'native', 'metadata'):
        return raw
    if raw.startswith('static/'):
        return raw
    if raw.startswith('native/'):
        relative = raw[len('native/'):]
        if any(relative.startswith(prefix + '/') for prefix in NATIVE_FILE_ROOTS):
            return raw
        if directory and (relative in NATIVE_FILE_ROOTS or relative == 'exvius'):
            return raw
        fail('Native path outside pinned Android installer allowlist')
    if raw == 'metadata/registry.json' and not directory:
        return raw
    fail('Unsupported ZIP member path (only static/, approved native/, or exact metadata/registry.json)')


def _collision(register: dict[str, str], path: str):
    # Register every prefix, not just the final filename. This rejects
    # collisions like static/Foo/a and static/foo/b on Android storage.
    bits = path.split('/')
    for i in range(1, len(bits) + 1):
        prefix = '/'.join(bits[:i])
        folded = prefix.casefold()
        prior = register.get(folded)
        if prior is not None and prior != prefix:
            fail('Casefold/Unicode parent or file path collision')
        register[folded] = prefix


def _reject_shape_conflicts(existing_files: set[str], path: str):
    bits = path.split('/')
    for i in range(1, len(bits)):
        if '/'.join(bits[:i]) in existing_files:
            fail('File used as parent directory')
    if any(x.startswith(path + '/') for x in existing_files):
        fail('Directory used as file')


def _reject_directory_conflicts(existing_files: set[str], directory: str):
    if directory in existing_files or any(directory.startswith(f + '/') for f in existing_files):
        fail('Directory marker conflicts with an existing file')


def _reject_file_marker_conflicts(directories: set[str], path: str):
    if path in directories or any(directory.startswith(path + '/') for directory in directories):
        fail('File conflicts with an explicit directory marker')


def _member_failure(pack_id: str, pack_order: int | None, member_index: int,
                    raw_name: str, is_dir: bool, reason: str) -> str:
    """Bounded ASCII-only first-error identity; does not print member contents."""
    name_hash = hashlib.sha256(raw_name.encode('utf-8', 'surrogatepass')).hexdigest()
    preview = ascii(raw_name)  # escapes control chars, newlines and non-ASCII
    if len(preview) > 144:
        preview = preview[:140] + '...'
    short_reason = ascii(reason)[1:-1][:150]
    return (f'pack={pack_id} pack_order_index={pack_order} member_index={member_index} '
            f'kind={"directory" if is_dir else "file"} path={preview} '
            f'path_sha256={name_hash} reason={short_reason}')


def pack_url_ok(url: str) -> bool:
    parsed = urllib.parse.urlsplit(url)
    return (parsed.scheme == 'https' and parsed.hostname == 'github.com'
            and parsed.username is None and parsed.password is None and parsed.port in (None, 443)
            and parsed.path.startswith('/Elvlin/exvius-offline/releases/download/')
            and parsed.path.endswith('.zip') and not parsed.query and not parsed.fragment)


def validate_index(index: dict, *, strict_revision: bool):
    if not isinstance(index, dict) or not isinstance(index.get('packs'), list):
        fail('Malformed index')
    packs = index['packs']
    if not packs or len(packs) > 1000:
        fail('Invalid pack count')
    if strict_revision:
        if (index.get('schema') != 1 or index.get('revision') != 13 or
            index.get('version') != '2026.11.16.13' or len(packs) != 23 or
            index.get('minAppVersionCode') != 9076 or
            index.get('metadata_source', {}).get('commit') != SOURCE_COMMIT or
            index.get('metadata_source', {}).get('git_blob_sha1') != SOURCE_BLOB):
            fail('Not the expected pinned revision-13 metadata')
    ids = set()
    urls = set()
    for item in packs:
        if not isinstance(item, dict):
            fail('Malformed pack object')
        name, url, sha, size, expanded = (item.get(k) for k in
                                          ('id', 'url', 'sha256', 'size', 'unpackedSize'))
        if not isinstance(name, str) or re.fullmatch(r'[A-Za-z0-9_-]{1,80}', name) is None or name in ids:
            fail('Bad or duplicate pack ID')
        if not isinstance(url, str) or not pack_url_ok(url) or url in urls:
            fail('Bad or duplicate release URL')
        if not isinstance(sha, str) or re.fullmatch('[a-f0-9]{64}', sha) is None:
            fail('Invalid archive SHA-256')
        if type(size) is not int or not 0 < size <= MAX_PACK_BYTES:
            fail('Invalid compressed pack size')
        if type(expanded) is not int or not 0 < expanded <= MAX_UNPACKED_BYTES:
            fail('Invalid unpacked pack size')
        ids.add(name)
        urls.add(url)
    if index.get('downloadBytes') != sum(p['size'] for p in packs):
        fail('Pack compressed total mismatch')
    if index.get('installedBytes') != sum(p['unpackedSize'] for p in packs):
        fail('Pack expanded total mismatch')
    if strict_revision and (index['downloadBytes'] != 18634180032 or index['installedBytes'] != 19052071696):
        fail('Pinned revision-13 aggregate mismatch')


class GitHubRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if (parsed.scheme != 'https' or parsed.hostname not in ALLOWED_HOSTS or
            parsed.username or parsed.password or parsed.port not in (None, 443)):
            fail('Redirect leaves approved GitHub asset hosts')
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def git_blob_sha1(raw: bytes) -> str:
    # Git object identity for the EXACT published metadata bytes, not JSON normalization.
    return hashlib.sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest()


def compare_pinned_source_metadata(raw: bytes, index: dict, expected_blob=SOURCE_BLOB):
    if len(raw) != 7110 and expected_blob == SOURCE_BLOB:
        fail('Pinned source metadata byte length changed')
    if git_blob_sha1(raw) != expected_blob:
        fail('Pinned source metadata Git blob SHA-1 mismatch')
    try:
        source = json.loads(raw.decode('utf-8'))
    except (UnicodeError, ValueError) as exc:
        fail('Pinned metadata is invalid UTF-8/JSON: %s' % type(exc).__name__)
    # Do not compare only totals or select entries; all 23 exact package identities matter.
    for key in ('schema','revision','version','minAppVersionCode','packs',
                'downloadBytes','installedBytes','files'):
        if source.get(key) != index.get(key):
            fail('Pinned metadata mismatch: %s' % key)
    return True


def verify_public_source_metadata(index: dict):
    url = ('https://raw.githubusercontent.com/' + SOURCE_REPO + '/' + SOURCE_COMMIT +
           '/data/latest.json')
    opener = urllib.request.build_opener(GitHubRedirect())
    with opener.open(urllib.request.Request(url, headers={'Accept-Encoding': 'identity',
                                                         'User-Agent': 'FFBE-Custom-Owner-Metadata/1.0'}),
                     timeout=30) as response:
        if response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
            fail('Unexpected metadata HTTP encoding')
        raw = response.read(20001)
    if len(raw) > 20000:
        fail('Oversized public metadata')
    return compare_pinned_source_metadata(raw, index)


def _download_one(item: dict, target: Path) -> None:
    if not pack_url_ok(item['url']):
        fail('Blocked URL')
    opener = urllib.request.build_opener(GitHubRedirect())
    req = urllib.request.Request(item['url'], headers={
        'User-Agent': 'FFBE-Custom-Owner-Manifest-Metadata/1.0',
        'Accept-Encoding': 'identity', 'Accept': 'application/octet-stream'})
    sha = hashlib.sha256()
    count = 0
    with opener.open(req, timeout=90) as response, target.open('xb') as out:
        if response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
            fail('HTTP content encoding not identity')
        declared = response.headers.get('Content-Length')
        if declared is not None and int(declared) != item['size']:
            fail('HTTP Content-Length mismatches pinned bytes')
        while True:
            block = response.read(CHUNK)
            if not block:
                break
            count += len(block)
            if count > item['size']:
                fail('Download exceeded pinned length')
            sha.update(block)
            out.write(block)
        out.flush()
        os.fsync(out.fileno())
    if count != item['size'] or sha.hexdigest() != item['sha256']:
        fail('Pack bytes or SHA-256 mismatch: ' + item['id'])


def verify_pack_bytes(file_path: Path, item: dict):
    if file_path.is_symlink() or not file_path.is_file():
        fail('Expected regular, nonsymlink archive')
    before = file_path.stat()
    if before.st_size != item['size'] or before.st_nlink > 1:
        fail('Pack size mismatch or hardlinked input')
    digest = hashlib.sha256()
    total = 0
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    fd = os.open(file_path, flags)
    try:
        start = os.fstat(fd)
        if not stat.S_ISREG(start.st_mode) or (start.st_dev, start.st_ino, start.st_size) != (before.st_dev, before.st_ino, before.st_size):
            fail('Pack changed before verify')
        while True:
            block = os.read(fd, CHUNK)
            if not block:
                break
            total += len(block)
            if total > item['size']:
                fail('Archive grew during hashing')
            digest.update(block)
        end = os.fstat(fd)
        after = file_path.stat()
        if (start.st_dev, start.st_ino, start.st_size, start.st_mtime_ns, start.st_ctime_ns) != (end.st_dev, end.st_ino, end.st_size, end.st_mtime_ns, end.st_ctime_ns) or (start.st_dev, start.st_ino, start.st_size, start.st_mtime_ns, start.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            fail('Pack changed during checksum')
    finally:
        os.close(fd)
    if total != item['size'] or digest.hexdigest() != item['sha256']:
        fail('Pinned archive hash mismatch: ' + item['id'])


def bridge_key(root_relative):
    for key, prefix, kind in BRIDGE_PATHS:
        if kind == 'file' and root_relative == prefix:
            return key
        if kind == 'dir' and root_relative.startswith(prefix + '/'):
            return key
    return None


def process_zip(path: Path, item: dict, global_register: dict, global_files: set,
                *, global_directories: set | None = None,
                accepted_directories: list | None = None,
                pack_order_index: int | None = None):
    entries = []
    members_seen = set()
    member_records = []
    local_register = {}
    local_files = set()
    local_directories = set()
    if global_directories is None:
        global_directories = set()
    total = 0
    try:
        with zipfile.ZipFile(path, 'r', allowZip64=True) as z:
            infos = z.infolist()
            if not infos or len(infos) > MAX_MEMBERS:
                fail('Invalid number of ZIP entries')
            for member_index, info in enumerate(infos):
                is_dir = info.is_dir()
                try:
                    raw_path = safe_path(info.filename, directory=is_dir)
                    if raw_path in members_seen:
                        fail('Duplicate ZIP member')
                    members_seen.add(raw_path)
                    _collision(local_register, raw_path)
                    if (info.flag_bits & 1 or info.compress_type not in ALLOWED_ARCHIVE_TYPES or
                        info.file_size < 0 or info.file_size > item['unpackedSize']):
                        fail('Encrypted/unsupported/oversized entry')
                    # A trailing slash alone does not prove an archive entry is a directory.
                    mode = stat.S_IFMT(info.external_attr >> 16)
                    if mode not in (0, stat.S_IFDIR if is_dir else stat.S_IFREG):
                        fail('Special/symlink or mismatched ZIP entry type')
                    if is_dir:
                        if info.file_size:
                            fail('Nonempty ZIP directory')
                        _reject_directory_conflicts(local_files, raw_path)
                        local_directories.add(raw_path)
                        member_records.append((member_index, raw_path, True, info.filename))
                        continue
                    _reject_shape_conflicts(local_files, raw_path)
                    _reject_file_marker_conflicts(local_directories, raw_path)
                    local_files.add(raw_path)
                    total += info.file_size
                    if total > item['unpackedSize']:
                        fail('Unpacked byte sum exceeded pinned value')
                    digest = hashlib.sha256()
                    read = 0
                    with z.open(info, mode='r') as src:
                        while True:
                            block = src.read(CHUNK)
                            if not block:
                                break
                            read += len(block)
                            if read > info.file_size:
                                fail('ZIP entry exceeded expected size')
                            digest.update(block)
                    if read != info.file_size:
                        fail('Incomplete ZIP member')
                    scope, mapped = raw_path.split('/', 1)
                    static_path = mapped if scope == 'static' else None
                    android_destination = ('exvius/data/' + raw_path if scope == 'static'
                                           else mapped if scope == 'native'
                                           else 'exvius/data/registry.json')
                    entries.append({
                        'archive_entry': raw_path, 'scope': scope,
                        'data_root_relative_path': static_path,
                        'android_installer_relative_destination': android_destination,
                        'bridge_path_key': bridge_key(mapped) if scope == 'static' else None,
                        'native_relative_path_unmapped': mapped if scope == 'native' else None,
                        'bytes': read, 'sha256': digest.hexdigest(),
                        'source_pack_id': item['id'], 'source_pack_sha256': item['sha256'],
                        'source_pack_url': item['url'], 'pack_order_index': None,
                        'zip_member_index': member_index,
                        'archive_checksum_verified': True,
                        'required_optional': 'UNKNOWN_NOT_AUTHENTICATED',
                        'per_file_external_provenance': 'PACK_ENTRY_ONLY',
                    })
                    member_records.append((member_index, raw_path, False, info.filename))
                except InventoryError as exc:
                    fail(_member_failure(item['id'], pack_order_index, member_index,
                                         info.filename, is_dir, str(exc)))
                except (OSError, EOFError, RuntimeError, zipfile.BadZipFile,
                        NotImplementedError) as exc:
                    fail(_member_failure(item['id'], pack_order_index, member_index,
                                         info.filename, is_dir,
                                         'ZIP member read error: ' + type(exc).__name__))
            if total != item['unpackedSize']:
                fail('Unpacked byte count mismatches pinned pack')
    except (OSError, EOFError, RuntimeError, zipfile.BadZipFile, NotImplementedError) as exc:
        fail('ZIP inspection failed closed: ' + type(exc).__name__)

    # Validate the complete pack before publishing any directory/file identities.
    # Overlaying exactly matching FILE paths across packs remains permitted.
    for member_index, raw_path, is_dir, original_name in member_records:
        try:
            _collision(global_register, raw_path)
            if is_dir:
                _reject_directory_conflicts(global_files, raw_path)
            else:
                _reject_shape_conflicts(global_files, raw_path)
                _reject_file_marker_conflicts(global_directories, raw_path)
        except InventoryError as exc:
            fail(_member_failure(item['id'], pack_order_index, member_index,
                                 original_name, is_dir, str(exc)))
    global_files.update(local_files)
    global_directories.update(local_directories)
    if accepted_directories is not None:
        accepted_directories.extend(sorted(local_directories))
    return entries


def _output_new_only(output_path: Path, payload: dict, input_dir: Path | None):
    output_path = output_path.absolute()
    if input_dir is not None:
        root = input_dir.resolve(strict=True)
        parent = output_path.parent.resolve(strict=True)
        if parent == root or root in parent.parents or str(parent).casefold().startswith(str(root).casefold().rstrip('/') + '/'):
            fail('Output must be outside the local input tree')
    if output_path.suffix.lower() != '.json' or not output_path.parent.is_dir() or output_path.exists() or output_path.is_symlink():
        fail('Output must be an unused .json file in an existing directory')
    raw = (json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + '\n').encode('utf-8')
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(output_path, flags, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        try:
            output_path.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(fd)


def process(index: dict, *, pack_dir: Path | None = None, allow_public: bool = False) -> dict:
    validate_index(index, strict_revision=allow_public)
    if (pack_dir is None) == (not allow_public):
        fail('Choose exactly one: local pack directory or explicitly authorized public downloads')
    if allow_public and os.environ.get('FFBE_AUTHORIZED_PUBLIC_PACK_DOWNLOADS') != 'YES':
        fail('Public pack processing must be authorized with environment variable')
    # A public run first re-authenticates the exact pinned data/latest.json blob,
    # so hand-transcribed pack rows cannot silently diverge from their source.
    if allow_public:
        verify_public_source_metadata(index)
    global_register = {}
    global_files = set()
    global_directories = set()
    file_entries = []
    pack_reports = []
    overwritten = {}
    if pack_dir is not None and (not pack_dir.is_dir() or pack_dir.is_symlink()):
        fail('Local pack directory not found or is symlink')
    for idx, item in enumerate(index['packs']):
        directories_seen = []
        filename = urllib.parse.urlsplit(item['url']).path.rsplit('/', 1)[-1]
        if not re.fullmatch(r'[A-Za-z0-9_.-]+\.zip', filename):
            fail('Invalid package filename')
        if pack_dir is None:
            with tempfile.TemporaryDirectory(prefix='ffbe_cloud_pack_') as temp:
                archive = Path(temp) / 'one-pack.zip'
                _download_one(item, archive)
                verify_pack_bytes(archive, item)
                entries = process_zip(archive, item, global_register, global_files,
                                      global_directories=global_directories,
                                      accepted_directories=directories_seen,
                                      pack_order_index=idx)
        else:
            archive = pack_dir / filename
            verify_pack_bytes(archive, item)
            stable_before = archive.stat()
            entries = process_zip(archive, item, global_register, global_files,
                                  global_directories=global_directories,
                                  accepted_directories=directories_seen,
                                  pack_order_index=idx)
            stable_after = archive.stat()
            if (stable_before.st_dev, stable_before.st_ino, stable_before.st_size,
                stable_before.st_mtime_ns, stable_before.st_ctime_ns) != (
                stable_after.st_dev, stable_after.st_ino, stable_after.st_size,
                stable_after.st_mtime_ns, stable_after.st_ctime_ns):
                fail('Local pack changed during ZIP inventory')
        for e in entries:
            e['pack_order_index'] = idx
            # Later packs with the same static path overwrite earlier at installer level.
            if e['scope'] == 'static':
                overwritten.setdefault(e['data_root_relative_path'], []).append(item['id'])
        file_entries.extend(entries)
        if len(file_entries) > MAX_TOTAL_MEMBERS:
            fail('Total inventory entry safety cap exceeded')
        pack_reports.append({'id': item['id'], 'archive_sha256': item['sha256'],
                             'archive_size_bytes': item['size'],
                             'unpacked_bytes_verified': item['unpackedSize'],
                             'files_hashed': len(entries),
                             'directory_markers_validated': len(directories_seen),
                             'order_index': idx})
    last_static = {}
    for row in file_entries:
        if row['scope'] == 'static':
            last_static[row['data_root_relative_path']] = row
    coverage = {}
    for key, prefix, kind in BRIDGE_PATHS:
        matches = [p for p in last_static if (p == prefix if kind == 'file' else p.startswith(prefix + '/'))]
        coverage[key] = {'relative_path': prefix,
                         'expected_kind': kind,
                         'matching_final_paths': len(matches),
                         'presence_in_indexed_packages': bool(matches),
                         'required_optional': 'UNKNOWN_NOT_AUTHENTICATED'}
    return {
        'schema': SCHEMA,
        'generated_utc': datetime.now(timezone.utc).isoformat(),
        'claimed_revision': index.get('revision'), 'claimed_version': index.get('version'),
        'pinned_source': index.get('metadata_source', {'status': 'SYNTHETIC_TEST_METADATA'}),
        'mode': 'PUBLIC_PACKS_SHA256_VERIFIED' if allow_public else 'SYNTHETIC_OR_LOCAL_TEST_PACKS',
        'pack_checksums_verified': True, 'file_checksums_calculated': True,
        'pinned_raw_metadata_git_blob_checked': allow_public,
        'resources_installed_or_extracted': False,
        'resource_root_completeness': 'UNVERIFIED',
        'android_runtime_requirements_verified': False,
        'required_optional_classification_verified': False,
        'build_status': 'HOLD_NOT_BUILDABLE',
        'holds_unchanged': ['NATIVE HOLD', 'Auto-Skip HOLD', 'repeat-stop HOLD',
                            'incomplete-source HOLD', 'original Sort/Filter type=0/order=1',
                            'Favorites First NO-GO'],
        'packs': pack_reports,
        'bridge_path_coverage': coverage,
        'pack_entries': file_entries,
        'static_overwrite_chains_in_pinned_pack_order': {p: seq for p, seq in overwritten.items() if len(seq) > 1},
        'summary': {'packs_verified': len(pack_reports), 'pack_entry_file_count': len(file_entries),
                    'unique_static_paths': len(last_static),
                    'native_entries_unmapped': sum(x['scope'] == 'native' for x in file_entries),
                    'metadata_registry_entries_hashed': sum(x['scope'] == 'metadata' for x in file_entries),
                    'directory_markers_validated': sum(x['directory_markers_validated'] for x in pack_reports),
                    'bridge_paths_with_matching_static_files': sum(x['presence_in_indexed_packages'] for x in coverage.values()),
                    'claimed_manifest_files_not_an_equivalence_check': index.get('files'),
                    'source_data_root_verified_complete': False},
        'limitations': [
            'Only a stream-hashed ZIP entry inventory; no actual Android data_root was assembled or tested.',
            'Pack list is transcribed from pinned public source metadata; PUBLIC mode checks the exact raw pinned Git blob before accessing packages.',
            'Static ZIP entry path is mapped to data_root relative path; native/ and metadata/registry.json entries are NOT bridge paths.',
            'Explicit directory markers are validated and counted but not treated as files.',
            'Later packs overwrite identical static paths in declared order; native installer behavior is not independently runtime verified.',
            'Nested game-assets.apk is only hashed as an opaque ZIP member; never opened or extracted.',
            'Required/optional/generated and seven-path completeness need independent authenticated source/runtime evidence.',
            'No application installation, game execution, build integration, save or protected-resource access has occurred.',
        ],
    }


def main(argv=None):
    p = argparse.ArgumentParser(description='FFBE revision-13 read-only streaming pack metadata inventory')
    p.add_argument('--index', required=True, type=Path, help='Pinned metadata index JSON')
    p.add_argument('--output', required=True, type=Path, help='New JSON output path outside local input')
    p.add_argument('--mode', choices=['local', 'public'], default='local')
    p.add_argument('--pack-dir', type=Path, help='Local synthetic/preexisting pack directory; mode=local only')
    p.add_argument('--allow-public-downloads', action='store_true', help='Explicit owner authorization; public mode only')
    args = p.parse_args(argv)
    try:
        if args.output.exists() or args.output.is_symlink():
            fail('Output exists (refuses overwrite)')
        if not args.index.is_file():
            fail('Index not present')
        with args.index.open('r', encoding='utf-8') as stream:
            index = json.load(stream)
        if args.mode == 'public':
            if not args.allow_public_downloads or args.pack_dir is not None:
                fail('Public mode requires explicit --allow-public-downloads and no --pack-dir')
            result = process(index, allow_public=True)
            _output_new_only(args.output, result, None)
        else:
            if args.pack_dir is None or args.allow_public_downloads:
                fail('Local mode requires --pack-dir and forbids public authorization flag')
            result = process(index, pack_dir=args.pack_dir)
            _output_new_only(args.output, result, args.pack_dir)
        print('SUCCESS: metadata only; packs verified=%d, entries hashed=%d; all build HOLDs retained' % (
            result['summary']['packs_verified'], result['summary']['pack_entry_file_count']))
        return 0
    except (InventoryError, OSError, ValueError, UnicodeError, TypeError, zipfile.BadZipFile) as exc:
        detail = str(exc)
        # A validated member failure has a bounded, ASCII-escaped diagnostic.
        # Preserve its complete filename digest and reason in cloud logs; unrelated
        # errors retain the previous 240-character output limit.
        member_detail = (isinstance(exc, InventoryError) and detail.startswith('pack=')
                         and ' member_index=' in detail and ' path_sha256=' in detail
                         and ' reason=' in detail)
        limit = 640 if member_detail else 240
        print('FAIL CLOSED (no accepted output): %s: %s' % (type(exc).__name__, detail[:limit]), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
