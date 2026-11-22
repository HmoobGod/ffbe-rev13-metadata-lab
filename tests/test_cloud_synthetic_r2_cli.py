"""R2 CLI-only synthetic diagnostics; no real resources or remote access."""
from __future__ import annotations

from contextlib import redirect_stderr
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ffbe_cloud_pack_inventory import InventoryError, main
from test_cloud_synthetic import index_from


ROOT = Path(__file__).resolve().parents[1]


class ZipCompatCliDiagnosticTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory(prefix='synthetic_ffbe_r2_cli_')
        self.addCleanup(td.cleanup)
        self.root = Path(td.name)
        self.packs = self.root / 'packs'
        self.packs.mkdir()
        self.output = self.root / 'output.json'
        self.index_file = self.root / 'index.json'

    def run_cli(self, name):
        index = index_from(self.packs, [[('static/mst_decoded/ok', b'ok'), (name, b'bad')]])
        self.index_file.write_text(json.dumps(index), encoding='utf-8')
        return subprocess.run(
            [sys.executable, '-B', str(ROOT / 'ffbe_cloud_pack_inventory.py'),
             '--mode', 'local', '--index', str(self.index_file),
             '--pack-dir', str(self.packs), '--output', str(self.output)],
            capture_output=True, text=True, timeout=20, check=False,
        )

    def test_60_long_malformed_path_cli_keeps_complete_identity_and_reason(self):
        name = 'unknown/\x1b\n' + 'z' * 600
        result = self.run_cli(name)
        stderr = result.stderr
        self.assertEqual(result.returncode, 2, stderr)
        self.assertFalse(self.output.exists())
        self.assertEqual(result.stdout, '')
        self.assertEqual(len(stderr.splitlines()), 1, stderr)
        self.assertLessEqual(len(stderr.rstrip('\n')), 710)
        self.assertIn('pack=test-000', stderr)
        self.assertIn('pack_order_index=0', stderr)
        self.assertIn('member_index=1', stderr)
        self.assertIn('kind=file', stderr)
        self.assertIn('path=', stderr)
        self.assertIn('...', stderr)
        self.assertIn(r'\x1b', stderr)
        self.assertIn(r'\n', stderr)
        self.assertNotIn('\x1b', stderr)
        self.assertIn('path_sha256=' + hashlib.sha256(name.encode('utf-8')).hexdigest(), stderr)
        self.assertIn('reason=Unsafe ZIP entry component', stderr)

    def test_61_short_unknown_prefix_cli_keeps_full_details(self):
        name = 'metadata/not_registry.json'
        result = self.run_cli(name)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(self.output.exists())
        self.assertEqual(len(result.stderr.splitlines()), 1, result.stderr)
        for field in ('pack=test-000', 'pack_order_index=0', 'member_index=1',
                      'kind=file', "path='metadata/not_registry.json'",
                      'path_sha256=' + hashlib.sha256(name.encode()).hexdigest(),
                      'reason=Unsupported ZIP member path'):
            self.assertIn(field, result.stderr)

    def test_62_generic_nonmember_error_remains_limited_to_240(self):
        index = index_from(self.packs, [[('static/mst_decoded/ok', b'ok')]])
        self.index_file.write_text(json.dumps(index), encoding='utf-8')
        err = io.StringIO()
        with patch('ffbe_cloud_pack_inventory.process', side_effect=InventoryError('Q' * 500)):
            with redirect_stderr(err):
                rc = main(['--mode', 'local', '--index', str(self.index_file),
                           '--pack-dir', str(self.packs), '--output', str(self.output)])
        self.assertEqual(rc, 2)
        message = err.getvalue()
        self.assertIn('Q' * 240, message)
        self.assertNotIn('Q' * 241, message)
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
