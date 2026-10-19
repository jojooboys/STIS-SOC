// Uji kontrak data dashboard tanpa browser menggunakan test runner bawaan Node.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import { dashboardData } from './dashboardData.js';

test('Flask snake_case counters render after login and paginated alerts remain visible', () => {
  const alert = { id: 1, rule_level: 12 };
  const data = dashboardData(
    { total_alerts: 14, alerts_today: 3, active_blocks: 2, critical_alerts: 1 },
    [], [], [], { items: [alert], total: 1, pages: 1 },
  );
  assert.deepEqual(Object.values(data.stats).map(value => value.toLocaleString()), ['14', '3', '2', '1']);
  assert.deepEqual(data.recentAlerts, [alert]);
});

test('missing data does not crash number formatting or list rendering', () => {
  const data = dashboardData(null, null, {}, null, null);
  assert.deepEqual(Object.values(data.stats).map(value => value.toLocaleString()), ['0', '0', '0', '0']);
  for (const key of ['timeline', 'severityDist', 'topSources', 'recentAlerts']) {
    assert.deepEqual(data[key], []);
  }
});
