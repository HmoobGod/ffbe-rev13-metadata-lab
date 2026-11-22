"""Synthetic only: never downloads actual FFBE resource archives or opens game files."""
from __future__ import annotations
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile

from ffbe_cloud_pack_inventory import (
    InventoryError, bridge_key, pack_url_ok, process, process_zip,
    safe_path, validate_index, verify_pack_bytes, _output_new_only,
    git_blob_sha1, compare_pinned_source_metadata,
)

ROOT = Path(__file__).resolve().parents[1]


def synthetic_zip(path: Path, members: list[tuple], compression=zipfile.ZIP_STORED):
    with zipfile.ZipFile(path, 'w', compression=compression) as z:
        for entry in members:
            if len(entry) == 3:
                name, data, is_symlink = entry
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                if is_symlink:
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                else:
                    info.external_attr = (stat.S_IFREG | 0o600) << 16
                z.writestr(info, data)
            else:
                name, data = entry
                z.writestr(name, data)
    content = path.read_bytes()
    return {'size':len(content), 'unpackedSize':sum(len(e[1]) for e in members),
            'sha256':hashlib.sha256(content).hexdigest()}


def index_from(d: Path, members_per_pack: list[list[tuple]]):
    packs = []
    for i, members in enumerate(members_per_pack):
        name = f'exvius-test-{i:03}.zip'
        props = synthetic_zip(d / name, members)
        packs.append({'id':f'test-{i:03}',
                      'url':f'https://github.com/Elvlin/exvius-offline/releases/download/test/{name}',
                      **props})
    return {'schema':1,'revision':13,'version':'synthetic-test-only',
            'packs':packs,
            'downloadBytes':sum(x['size'] for x in packs),
            'installedBytes':sum(x['unpackedSize'] for x in packs),
            'files':0}


class CloudManifestTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory(prefix='synthetic_ffbe_')
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)
        self.packs = self.root / 'packs'
        self.packs.mkdir()

    def run_local(self, members):
        index = index_from(self.packs, members)
        return process(index, pack_dir=self.packs)

    def test_01_pinned_manifest_23_public_metadata_only(self):
        pinned = json.loads((ROOT/'revision13_packs.json').read_text())
        validate_index(pinned, strict_revision=True)
        self.assertEqual(len(pinned['packs']), 23)
        self.assertEqual(pinned['downloadBytes'], 18634180032)
        self.assertEqual(pinned['installedBytes'], 19052071696)

    def test_02_single_synthetic_pack(self):
        report = self.run_local([[('static/mst_decoded/fake.ndjson', b'dummy')]])
        self.assertEqual(report['summary']['packs_verified'], 1)
        self.assertEqual(report['pack_entries'][0]['sha256'],hashlib.sha256(b'dummy').hexdigest())
        self.assertEqual(report['bridge_path_coverage']['MST_DIR']['matching_final_paths'],1)

    def test_03_23_tiny_synthetic_packs(self):
        packs = [[(f'static/mst_decoded/synthetic_{i:02}.bin',bytes([i]))] for i in range(23)]
        report=self.run_local(packs)
        self.assertEqual(report['summary']['packs_verified'],23)
        self.assertEqual(report['summary']['unique_static_paths'],23)
        self.assertFalse(report['summary']['source_data_root_verified_complete'])

    def test_04_seven_bridge_paths(self):
        paths=['mst_decoded/f','text_decoded/f','cpk_extract/f',
               'client/files/f','gacha_community/art/f','overlay/f',
               'client/shared_prefs/gamedata.xml']
        result=self.run_local([[('static/'+x,b'x') for x in paths]])
        self.assertEqual(result['summary']['bridge_paths_with_matching_static_files'],7)
        self.assertTrue(all(x['presence_in_indexed_packages'] for x in result['bridge_path_coverage'].values()))

    def test_05_native_not_bridge(self):
        result=self.run_local([[('native/mst/synthetic.dat',b'abc')]])
        self.assertIsNone(result['pack_entries'][0]['data_root_relative_path'])
        self.assertEqual(result['summary']['native_entries_unmapped'],1)

    def test_06_overlay_last_pack_wins(self):
        report=self.run_local([[('static/mst_decoded/x',b'older')],[('static/mst_decoded/x',b'newer')]])
        self.assertEqual(report['summary']['unique_static_paths'],1)
        self.assertEqual(report['static_overwrite_chains_in_pinned_pack_order']['mst_decoded/x'],['test-000','test-001'])

    def test_07_opaque_nested_apk_entry(self):
        report=self.run_local([[('static/client/game-assets.apk',b'opaque-fake-bytes')]])
        self.assertIsNone(report['pack_entries'][0]['bridge_path_key'])
        self.assertEqual(report['pack_entries'][0]['sha256'], hashlib.sha256(b'opaque-fake-bytes').hexdigest())

    def test_08_zip_slip_parent_rejected(self):
        with self.assertRaises(InventoryError):self.run_local([[('static/../bad',b'x')]])

    def test_09_absolute_path_rejected(self):
        with self.assertRaises(InventoryError):self.run_local([[('/static/mst_decoded/f',b'x')]])

    def test_10_backslash_rejected(self):
        with self.assertRaises(InventoryError):self.run_local([[('static\\mst_decoded\\x',b'x')]])

    def test_11_noncanonical_dot_segment_rejected(self):
        with self.assertRaises(InventoryError):self.run_local([[('static/./mst_decoded/x',b'x')]])

    def test_12_duplicate_archive_entries_rejected(self):
        with self.assertRaises(InventoryError):self.run_local([[('static/mst_decoded/x',b'one'),('static/mst_decoded/x',b'two')]])

    def test_13_casefold_collision_rejected(self):
        with self.assertRaises(InventoryError):self.run_local([[('static/mst_decoded/Foo',b'a'),('static/mst_decoded/foo',b'b')]])

    def test_14_crosspack_casefold_collision_rejected(self):
        with self.assertRaises(InventoryError):self.run_local([[('static/mst_decoded/Foo',b'a')],[('static/mst_decoded/foo',b'b')]])

    def test_15_symlink_zip_entry_rejected(self):
        with self.assertRaises(InventoryError):self.run_local([[('static/mst_decoded/link',b'elsewhere',True)]])

    def test_16_special_prefix_rejected(self):
        with self.assertRaises(InventoryError):self.run_local([[('save/active.sav',b'never')]])

    def test_17_invalid_archive_hash_rejected(self):
        idx=index_from(self.packs,[[('static/mst_decoded/x',b'x')]])
        idx['packs'][0]['sha256']='0'*64
        with self.assertRaises(InventoryError):process(idx,pack_dir=self.packs)

    def test_18_unpacked_size_mismatch_rejected(self):
        idx=index_from(self.packs,[[('static/mst_decoded/x',b'x')]])
        idx['packs'][0]['unpackedSize']+=1
        idx['installedBytes']+=1
        with self.assertRaises(InventoryError):process(idx,pack_dir=self.packs)

    def test_19_missing_pack_rejected(self):
        idx=index_from(self.packs,[[('static/mst_decoded/x',b'x')]])
        (self.packs/'exvius-test-000.zip').unlink()
        with self.assertRaises((OSError,InventoryError)):process(idx,pack_dir=self.packs)

    def test_20_output_cannot_be_inside_input(self):
        idx=index_from(self.packs,[[('static/mst_decoded/x',b'x')]])
        report=process(idx,pack_dir=self.packs)
        with self.assertRaises(InventoryError):_output_new_only(self.packs/'manifest.json',report,self.packs)
        self.assertFalse((self.packs/'manifest.json').exists())

    def test_21_output_exclusive_and_metadata_only(self):
        report=self.run_local([[('static/mst_decoded/x',b'only-synthetic')]])
        out=self.root/'manifest.json'
        _output_new_only(out,report,self.packs)
        self.assertEqual(json.loads(out.read_text())['build_status'],'HOLD_NOT_BUILDABLE')
        with self.assertRaises(InventoryError):_output_new_only(out,report,self.packs)

    def test_22_public_mode_requires_explicit_env(self):
        idx=index_from(self.packs,[[('static/mst_decoded/x',b'x')]])
        old=os.environ.pop('FFBE_AUTHORIZED_PUBLIC_PACK_DOWNLOADS',None)
        try:
            with self.assertRaises(InventoryError):process(idx, allow_public=True)
        finally:
            if old is not None:os.environ['FFBE_AUTHORIZED_PUBLIC_PACK_DOWNLOADS']=old

    def test_23_reject_non_github_pack_url(self):
        idx=index_from(self.packs,[[('static/mst_decoded/x',b'x')]])
        idx['packs'][0]['url']='https://example.com/pack.zip'
        with self.assertRaises(InventoryError):validate_index(idx, strict_revision=False)

    def test_24_crosspack_file_parent_conflict(self):
        with self.assertRaises(InventoryError):self.run_local([[('static/mst_decoded/a',b'x')],[('static/mst_decoded/a/f',b'y')]])

    def test_25_crc_corruption_rejected(self):
        idx=index_from(self.packs,[[('static/mst_decoded/x',b'hello')]])
        file=self.packs/'exvius-test-000.zip'
        content=bytearray(file.read_bytes())
        # Flip the plaintext data and update the pack digest only; ZIP CRC must fail.
        pos=content.find(b'hello')
        self.assertGreater(pos,0)
        content[pos]^=0x01
        file.write_bytes(content)
        idx['packs'][0]['sha256']=hashlib.sha256(content).hexdigest()
        with self.assertRaises(InventoryError):process(idx,pack_dir=self.packs)

    def test_26_bridge_key_outside_paths(self):
        self.assertIsNone(bridge_key('client/game-assets.apk'))
        self.assertEqual(bridge_key('client/shared_prefs/gamedata.xml'),'VERSION_TABLE_XML')

    def test_27_reject_control_char(self):
        with self.assertRaises(InventoryError):safe_path('static/foo/\x1f')

    def test_29_casefold_parent_directory_alias_refused(self):
        with self.assertRaises(InventoryError):
            self.run_local([[('static/mst_decoded/Folder/a',b'a'),
                             ('static/mst_decoded/folder/b',b'b')]])

    def test_30_crosspack_casefold_parent_alias_refused(self):
        with self.assertRaises(InventoryError):
            self.run_local([[('static/mst_decoded/Folder/a',b'a')],
                             [('static/mst_decoded/folder/b',b'b')]])

    def test_31_file_parent_reverse_conflict(self):
        with self.assertRaises(InventoryError):
            self.run_local([[('static/mst_decoded/a/f',b'x')],
                             [('static/mst_decoded/a',b'y')]])

    def test_32_git_blob_authentication_pure_synthetic(self):
        raw=b'{"packs": []}'
        expect=git_blob_sha1(raw)
        with self.assertRaises(InventoryError):
            compare_pinned_source_metadata(raw, {'packs':[], 'files':1}, expected_blob=expect)
        self.assertRegex(expect, r'^[a-f0-9]{40}$')

    def test_33_pinned_source_metadata_tampering_rejected(self):
        raw=b'{"schema":1,"packs":[]}'
        with self.assertRaises(InventoryError):
            compare_pinned_source_metadata(raw+b' ', {}, expected_blob=git_blob_sha1(raw))

    def test_34_github_public_source_check_cannot_be_skipped(self):
        idx=json.loads((ROOT/'revision13_packs.json').read_text())
        self.assertEqual(idx['metadata_source']['git_blob_sha1'],
                         'b79394fdf70c88a841d8600ea89d35fcc77b411c')

    def test_28_casefold_output_alias(self):
        report=self.run_local([[('static/mst_decoded/x',b'x')]])
        with self.assertRaises(InventoryError):_output_new_only(self.packs/'out.json', report, self.packs)


if __name__ == '__main__':
    unittest.main()
