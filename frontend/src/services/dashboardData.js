// Petakan snake_case API ke model tampilan dan sediakan nilai kosong yang aman.
export function dashboardData(stats, timeline, severity, sources, alerts) {
  return {
    stats: {
      totalAlerts: stats?.total_alerts ?? 0,
      alertsToday: stats?.alerts_today ?? 0,
      activeBlocks: stats?.active_blocks ?? 0,
      criticalAlerts: stats?.critical_alerts ?? 0,
    },
    timeline: Array.isArray(timeline) ? timeline : [],
    severityDist: Array.isArray(severity) ? severity : [],
    topSources: Array.isArray(sources) ? sources : [],
    recentAlerts: Array.isArray(alerts?.items) ? alerts.items : [],
  };
}
