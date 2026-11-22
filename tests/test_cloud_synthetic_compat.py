"""Additional local-only synthetic ZIP compatibility tests; no public resource reads."""
from __future__ import annotations

import hashlib
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile

from ffbe_cloud_pack_inventory import InventoryError, process, safe_path
from test_cloud_synthetic import index_from, synthetic_zip


class ZipCompatRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='synthetic_ffbe_zip_compat_')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pack_dir = self.root / 'synthetic'
        self.pack_dir.mkdir()

    def run_local(self, packs):
        index = index_from(self.pack_dir, packs)
        return process(index, pack_dir=self.pack_dir)

    def test_35_exact_registry_entry_maps_to_original_installer_destination(self):
        report = self.run_local([[('metadata/registry.json', b'{"synthetic":true}'),
                                  ('static/mst_decoded/fake.ndjson', b'{}')]])
        entry = next(e for e in report['pack_entries'] if e['scope'] == 'metadata')
        self.assertEqual(entry['archive_entry'], 'metadata/registry.json')
        self.assertEqual(entry['android_installer_relative_destination'], 'exvius/data/registry.json')
        self.assertIsNone(entry['data_root_relative_path'])
        self.assertIsNone(entry['bridge_path_key'])
        self.assertEqual(report['summary']['metadata_registry_entries_hashed'], 1)
        self.assertEqual(report['summary']['unique_static_paths'], 1)
        self.assertEqual(report['summary']['pack_entry_file_count'], 2)

    def test_36_root_and_nested_directory_markers_are_validated_not_hashed(self):
        members = [('static/', b''), ('static/mst_decoded/', b''),
                   ('native/', b''), ('native/mst/', b''),
                   ('native/exvius/', b''), ('native/exvius/equipment-enhancement/', b''),
                   ('metadata/', b''), ('static/mst_decoded/x', b'x')]
        report = self.run_local([members])
        self.assertEqual(report['summary']['directory_markers_validated'], 7)
        self.assertEqual(report['packs'][0]['directory_markers_validated'], 7)
        self.assertEqual(report['summary']['pack_entry_file_count'], 1)
        self.assertEqual(report['pack_entries'][0]['archive_entry'], 'static/mst_decoded/x')

    def test_37_duplicate_directory_markers_in_one_pack_fail_closed(self):
        with self.assertRaisesRegex(InventoryError, 'Duplicate ZIP member'):
            self.run_local([[('static/', b''), ('static/', b''),
                             ('static/mst_decoded/x', b'x')]])

    def test_38_repeat_same_directory_across_packs_is_safe(self):
        report = self.run_local([[('static/', b''), ('static/mst_decoded/a', b'a')],
                                 [('static/', b''), ('static/mst_decoded/b', b'b')]])
        self.assertEqual(report['summary']['directory_markers_validated'], 2)
        self.assertEqual(report['summary']['unique_static_paths'], 2)

    def test_39_bad_prefix_directory_is_not_silently_skipped(self):
        with self.assertRaisesRegex(InventoryError, 'Unsupported ZIP member path'):
            self.run_local([[('unknown/', b''), ('static/mst_decoded/x', b'x')]])

    def test_40_bad_metadata_file_is_rejected(self):
        with self.assertRaisesRegex(InventoryError, 'Unsupported ZIP member path'):
            self.run_local([[('metadata/random.json', b'{}')]])

    def test_41_bad_metadata_subdirectory_is_rejected(self):
        with self.assertRaisesRegex(InventoryError, 'Unsupported ZIP member path'):
            self.run_local([[('metadata/extra/', b''), ('metadata/registry.json', b'x')]])

    def test_42_registry_json_is_not_a_directory(self):
        with self.assertRaisesRegex(InventoryError, 'Unsupported ZIP member path'):
            self.run_local([[('metadata/registry.json/', b''), ('static/mst_decoded/x', b'x')]])

    def test_43_registry_stem_is_not_an_accepted_file(self):
        with self.assertRaises(InventoryError):
            safe_path('metadata')
        with self.assertRaises(InventoryError):
            safe_path('native')
        with self.assertRaises(InventoryError):
            safe_path('static')

    def test_44_native_installer_file_allowlist_exact(self):
        names = ('mst/test.dat', 'localized_texts/fixture.xml',
                 'common_lang/a', 'en/b', 'homeMarquee/c',
                 'exvius/equipment-enhancement/d')
        report = self.run_local([[('native/' + n, b'x') for n in names]])
        self.assertEqual(report['summary']['native_entries_unmapped'], len(names))
        for e, n in zip(report['pack_entries'], names):
            self.assertEqual(e['android_installer_relative_destination'], n)
            self.assertIsNone(e['data_root_relative_path'])

    def test_45_native_unapproved_file_subtree_rejected(self):
        for bad in ('native/other/x', 'native/exvius/other/x',
                    'native/mst_other/x', 'native/mst',
                    'native/exvius/equipment-enhancement'):
            with self.subTest(bad=bad), self.assertRaisesRegex(InventoryError, 'Native path outside'):
                safe_path(bad)

    def test_46_native_unapproved_directory_subtree_rejected(self):
        for bad in ('native/other/', 'native/exvius/wrong/', 'native/mst_other/'):
            with self.subTest(bad=bad), self.assertRaisesRegex(InventoryError, 'Native path outside'):
                safe_path(bad, directory=True)

    def test_47_crosspack_directory_after_parent_file_rejected(self):
        with self.assertRaisesRegex(InventoryError, 'Directory marker conflicts with an existing file'):
            self.run_local([[('static/a', b'a')],
                            [('static/a/b/', b''), ('static/another', b'z')]])

    def test_48_crosspack_file_after_child_directory_rejected(self):
        with self.assertRaisesRegex(InventoryError, 'File conflicts with an explicit directory marker'):
            self.run_local([[('static/a/b/', b''), ('static/another', b'z')],
                            [('static/a', b'a')]])

    def test_49_crosspack_file_same_as_directory_marker_rejected(self):
        with self.assertRaisesRegex(InventoryError, 'File conflicts with an explicit directory marker'):
            self.run_local([[('static/a/', b''), ('static/b', b'b')],
                            [('static/a', b'a')]])

    def test_50_casefold_directory_parent_collision_rejected(self):
        with self.assertRaisesRegex(InventoryError, 'Casefold/Unicode'):
            self.run_local([[('static/Folder/', b''), ('static/folder/x', b'x')]])

    def test_51_nonempty_directory_marker_rejected(self):
        with self.assertRaisesRegex(InventoryError, 'Nonempty ZIP directory'):
            self.run_local([[('static/something/', b'notempty'),
                             ('static/mst_decoded/x', b'x')]])

    def test_52_trailing_slash_marked_as_regular_file_rejected(self):
        fname = self.pack_dir / 'exvius-test-000.zip'
        with zipfile.ZipFile(fname, 'w') as z:
            info = zipfile.ZipInfo('static/mst_decoded/')
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            z.writestr(info, b'')
            z.writestr('static/mst_decoded/x', b'x')
        raw = fname.read_bytes()
        index = {'schema':1, 'revision':13, 'version':'synthetic-test-only',
                 'packs':[{'id':'test-000', 'url':'https://github.com/Elvlin/exvius-offline/releases/download/test/exvius-test-000.zip',
                           'size':len(raw), 'unpackedSize':1, 'sha256':hashlib.sha256(raw).hexdigest()}],
                 'downloadBytes':len(raw), 'installedBytes':1, 'files':0}
        with self.assertRaisesRegex(InventoryError, 'mismatched ZIP entry type'):
            process(index, pack_dir=self.pack_dir)

    def test_53_first_member_diagnostic_has_pack_order_kind_index_and_hash(self):
        name = 'metadata/unknown.json'
        with self.assertRaises(InventoryError) as caught:
            self.run_local([[('static/mst_decoded/x', b'x'), (name, b'bad')]])
        message = str(caught.exception)
        self.assertIn('pack=test-000', message)
        self.assertIn('pack_order_index=0', message)
        self.assertIn('member_index=1', message)
        self.assertIn('kind=file', message)
        self.assertIn('path_sha256=' + hashlib.sha256(name.encode()).hexdigest(), message)
        self.assertIn('Unsupported ZIP member path', message)

    def test_54_diagnostic_is_bounded_and_escapes_control_characters(self):
        name = 'unknown/' + 'z' * 600 + '\x1b' + '\n'
        with self.assertRaises(InventoryError) as caught:
            self.run_local([[('static/mst_decoded/ok', b'ok'), (name, b'bad')]])
        message = str(caught.exception)
        self.assertLess(len(message), 450)
        self.assertNotIn('\x1b', message)
        self.assertNotIn('\n', message)
        self.assertIn('...', message)  # clipped path; full name identified by digest
        self.assertIn('path_sha256=' + hashlib.sha256(name.encode()).hexdigest(), message)

    def test_59_short_control_character_is_escaped_in_diagnostic(self):
        name = 'strange/\x1bnewline\n'
        with self.assertRaises(InventoryError) as caught:
            self.run_local([[('static/mst_decoded/ok', b'ok'), (name, b'bad')]])
        msg = str(caught.exception)
        self.assertIn('\\x1b', msg)
        self.assertIn('\\n', msg)
        self.assertNotIn('\x1b', msg)
        self.assertNotIn('\n', msg)

    def test_55_unknown_directory_with_file_stays_fail_closed(self):
        with self.assertRaises(InventoryError) as caught:
            self.run_local([[('unknown/', b''), ('unknown/thing', b'bad'),
                             ('static/mst_decoded/ok', b'ok')]])
        self.assertIn('member_index=0', str(caught.exception))

    def test_56_directory_marker_conflicts_with_local_file_in_reverse(self):
        with self.assertRaises(InventoryError):
            self.run_local([[('static/a', b'a'), ('static/a/sub/', b''),
                             ('static/b', b'b')]])

    def test_57_native_directory_with_traversal_rejected(self):
        with self.assertRaises(InventoryError):
            self.run_local([[('native/mst/../other/', b''), ('static/mst_decoded/x', b'x')]])

    def test_58_registry_overlay_is_tracked_without_static_bridge_inflation(self):
        report = self.run_local([[('metadata/registry.json', b'old')],
                                 [('metadata/registry.json', b'new')]])
        self.assertEqual(report['summary']['metadata_registry_entries_hashed'], 2)
        self.assertEqual(report['summary']['unique_static_paths'], 0)
        self.assertEqual(report['summary']['bridge_paths_with_matching_static_files'], 0)
        self.assertEqual([x['pack_order_index'] for x in report['pack_entries']], [0, 1])


if __name__ == '__main__':
    unittest.main()
