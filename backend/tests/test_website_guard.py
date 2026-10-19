"""Uji baseline, perubahan file, pola konten, dan direktori yang dikecualikan dengan file sementara."""

import json
import tempfile
import unittest
from pathlib import Path

from website_guard.website_guard import create_baseline, scan


class WebsiteGuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.root = self.base / 'web1'
        self.state = self.base / 'state'
        self.log = self.base / 'website_guard.log'
        self.root.mkdir()
        (self.root / 'index.php').write_text('<?php echo "Welcome"; ?>', encoding='utf-8')
        self.baseline = self.state / 'baseline.json'
        self.seen = self.state / 'seen.json'

    def tearDown(self):
        self.temporary.cleanup()

    def test_detects_content_injection_and_deduplicates_unchanged_finding(self):
        create_baseline(self.root, self.baseline, self.seen)
        (self.root / 'index.php').write_text(
            '<?php echo "situs slot gacor dan judi online"; ?>',
            encoding='utf-8',
        )

        first = scan(self.root, self.baseline, self.seen, self.log)
        second = scan(self.root, self.baseline, self.seen, self.log)

        self.assertEqual(first['status'], 'threats_found')
        self.assertEqual(first['findings'], 2)  # content plus integrity change
        self.assertEqual(first['new_events'], 2)
        self.assertEqual(second['new_events'], 0)
        events = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual({event['event_type'] for event in events}, {
            'web_content_threat', 'web_integrity_change',
        })
        content_event = next(event for event in events if event['event_type'] == 'web_content_threat')
        self.assertEqual(content_event['threat_type'], 'gambling_spam')

    def test_baseline_refuses_known_suspicious_content(self):
        (self.root / 'index.php').write_text('Promo pinjaman online cair cepat', encoding='utf-8')
        with self.assertRaisesRegex(RuntimeError, 'Refusing to approve suspicious content'):
            create_baseline(self.root, self.baseline, self.seen)

    def test_flags_webshell_shaped_file_without_executing_it(self):
        create_baseline(self.root, self.baseline, self.seen)
        (self.root / 'marker.txt').write_text(
            '<?php eval(base64_decode("TEST_ONLY")); ?>', encoding='utf-8'
        )
        result = scan(self.root, self.baseline, self.seen, self.log)
        self.assertEqual(result['status'], 'threats_found')
        events = [json.loads(line) for line in self.log.read_text().splitlines()]
        content = next(item for item in events if item['event_type'] == 'web_content_threat')
        self.assertEqual(content['threat_type'], 'webshell_code')
        self.assertEqual(content['file_path'], str(self.root / 'marker.txt'))

    def test_detects_added_symlink_as_critical_integrity_event(self):
        create_baseline(self.root, self.baseline, self.seen)
        try:
            (self.root / 'backdoor.php').symlink_to(self.root / 'index.php')
        except (OSError, NotImplementedError):
            self.skipTest('Symlink creation is not available in this environment')

        result = scan(self.root, self.baseline, self.seen, self.log)

        self.assertEqual(result['new_events'], 1)
        event = json.loads(self.log.read_text().strip())
        self.assertEqual(event['event_type'], 'web_integrity_change')
        self.assertEqual(event['change_type'], 'symlink')
