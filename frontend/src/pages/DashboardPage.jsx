// Gabungkan ringkasan API menjadi kartu, grafik, dan daftar alert terbaru.
import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Shield,
  AlertTriangle,
  ShieldBan,
  Flame,
  Loader2,
  RefreshCw,
  ArrowRight
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend
} from 'recharts';
import api from '../services/api';
import { dashboardData } from '../services/dashboardData';
import toast from 'react-hot-toast';
import clsx from 'clsx';

const COLORS = {
  Critical: '#ef4444', // soc-danger / red-500
  High: '#f59e0b',     // soc-warning / amber-500
  Medium: '#3b82f6',   // soc-accent / blue-500
  Low: '#22c55e'       // soc-success / green-500
};

const DashboardPage = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [data, setData] = useState({
    stats: { totalAlerts: 0, alertsToday: 0, activeBlocks: 0, criticalAlerts: 0 },
    timeline: [],
    severityDist: [],
    topSources: [],
    recentAlerts: []
  });

  const fetchData = async () => {
    setLoading(true);
    setLoadError('');
    try {
      const [statsRes, timelineRes, severityRes, topSourcesRes, alertsRes] = await Promise.all([
        api.getStats(),
        api.getTimeline(),
        api.getSeverityDistribution(),
        api.getTopSources(),
        api.getAlerts({ per_page: 10 })
      ]);

      setData(dashboardData(statsRes.data, timelineRes.data, severityRes.data, topSourcesRes.data, alertsRes.data));
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
      setLoadError('Dashboard data could not be loaded. Check the backend connection and try Refresh.');
      toast.error('Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleBlockIP = async (ip) => {
    try {
      await api.blockIP(ip, 'Quick block from Dashboard');
      toast.success(`IP ${ip} blocked successfully`);
      fetchData(); // Refresh data
    } catch (error) {
      toast.error(error.response?.data?.message || `Failed to block IP ${ip}`);
    }
  };

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center text-slate-300">
        <Loader2 className="h-8 w-8 animate-spin text-soc-accent" />
        <span className="ml-3 text-lg font-medium">Loading Dashboard...</span>
      </div>
    );
  }

  const { stats, timeline, severityDist, topSources, recentAlerts } = data;

  return (
    <div className="space-y-6">
      {loadError && <p role="alert" className="rounded-lg border border-red-500 p-4 text-red-400">{loadError}</p>}
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">SOC Dashboard</h1>
          <p className="text-sm text-slate-400">Overview of system security events and alerts</p>
        </div>
        <button
          onClick={fetchData}
          className="flex items-center gap-2 px-4 py-2 bg-soc-card border border-soc-border rounded-lg text-slate-300 hover:text-white hover:bg-soc-dark/50 transition-colors"
        >
          <RefreshCw className="h-4 w-4" />
          Refresh
        </button>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Alerts */}
        <div className="bg-soc-card rounded-xl border border-soc-border p-6 flex items-center">
          <div className="p-3 rounded-lg bg-blue-500/10 text-soc-accent">
            <Shield className="h-8 w-8" />
          </div>
          <div className="ml-4">
            <p className="text-sm font-medium text-slate-400">Total Alerts</p>
            <p className="text-2xl font-bold text-white">{stats.totalAlerts.toLocaleString()}</p>
          </div>
        </div>

        {/* Alerts Today */}
        <div className="bg-soc-card rounded-xl border border-soc-border p-6 flex items-center">
          <div className="p-3 rounded-lg bg-amber-500/10 text-soc-warning">
            <AlertTriangle className="h-8 w-8" />
          </div>
          <div className="ml-4">
            <p className="text-sm font-medium text-slate-400">Alerts Today</p>
            <p className="text-2xl font-bold text-white">{stats.alertsToday.toLocaleString()}</p>
          </div>
        </div>

        {/* Active Blocks */}
        <div className="bg-soc-card rounded-xl border border-soc-border p-6 flex items-center">
          <div className="p-3 rounded-lg bg-red-500/10 text-soc-danger">
            <ShieldBan className="h-8 w-8" />
          </div>
          <div className="ml-4">
            <p className="text-sm font-medium text-slate-400">Active Blocks</p>
            <p className="text-2xl font-bold text-white">{stats.activeBlocks.toLocaleString()}</p>
          </div>
        </div>

        {/* Critical Alerts */}
        <div className="bg-soc-card rounded-xl border border-soc-border p-6 flex items-center">
          <div className="p-3 rounded-lg bg-red-600/10 text-soc-critical">
            <Flame className="h-8 w-8" />
          </div>
          <div className="ml-4">
            <p className="text-sm font-medium text-slate-400">Critical Alerts</p>
            <p className="text-2xl font-bold text-white">{stats.criticalAlerts.toLocaleString()}</p>
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline Chart */}
        <div className="lg:col-span-2 bg-soc-card rounded-xl border border-soc-border p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Alerts Timeline (24h)</h2>
          <div className="h-72">
            {timeline.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                  <XAxis
                    dataKey="hour"
                    stroke="#94a3b8"
                    fontSize={12}
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis
                    stroke="#94a3b8"
                    fontSize={12}
                    tickLine={false}
                    axisLine={false}
                  />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#f8fafc' }}
                    itemStyle={{ color: '#3b82f6' }}
                  />
                  <Area
                    type="monotone"
                    dataKey="count"
                    stroke="#3b82f6"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorCount)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-400">No timeline data available</div>
            )}
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="bg-soc-card rounded-xl border border-soc-border p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Severity Distribution</h2>
          <div className="h-72">
            {severityDist.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityDist}
                    innerRadius={60}
                    outerRadius={80}
                    paddingAngle={5}
                    dataKey="value"
                    nameKey="name"
                    stroke="none"
                  >
                    {severityDist.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[entry.name] || '#94a3b8'} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#f8fafc', borderRadius: '8px' }}
                  />
                  <Legend verticalAlign="bottom" height={36} iconType="circle" />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-400">No severity data available</div>
            )}
          </div>
        </div>
      </div>

      {/* Tables Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Top Source IPs */}
        <div className="bg-soc-card rounded-xl border border-soc-border overflow-hidden">
          <div className="p-4 border-b border-soc-border bg-soc-card">
            <h2 className="text-lg font-semibold text-white">Top Source IPs</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="text-xs text-slate-400 uppercase bg-soc-dark/50 border-b border-soc-border">
                <tr>
                  <th className="px-4 py-3">IP Address</th>
                  <th className="px-4 py-3 text-center">Alerts</th>
                  <th className="px-4 py-3 text-center">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border">
                {topSources.length > 0 ? topSources.map((source, idx) => (
                  <tr key={idx} className="hover:bg-soc-dark/50 transition-colors">
                    <td className="px-4 py-3 font-medium text-slate-300">{source.ip}</td>
                    <td className="px-4 py-3 text-center text-slate-400">{source.count}</td>
                    <td className="px-4 py-3 text-center">
                      <button
                        onClick={() => handleBlockIP(source.ip)}
                        className="p-1 rounded text-slate-400 hover:text-white hover:bg-soc-danger transition-colors"
                        title="Block IP"
                      >
                        <ShieldBan className="h-4 w-4" />
                      </button>
                    </td>
                  </tr>
                )) : (
                  <tr>
                    <td colSpan="3" className="px-4 py-8 text-center text-slate-500">
                      No source IP data found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent Alerts */}
        <div className="lg:col-span-2 bg-soc-card rounded-xl border border-soc-border overflow-hidden">
          <div className="p-4 border-b border-soc-border bg-soc-card flex justify-between items-center">
            <h2 className="text-lg font-semibold text-white">Recent Alerts</h2>
            <Link to="/alerts" className="text-sm text-soc-accent hover:text-blue-400 flex items-center gap-1">
              View All <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="text-xs text-slate-400 uppercase bg-soc-dark/50 border-b border-soc-border">
                <tr>
                  <th className="px-4 py-3">Time</th>
                  <th className="px-4 py-3">Rule</th>
                  <th className="px-4 py-3 text-center">Level</th>
                  <th className="px-4 py-3">Source IP</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border">
                {recentAlerts.length > 0 ? recentAlerts.map((alert, idx) => {
                  const level = alert.rule_level;
                  const levelColor = level >= 12 ? 'bg-red-500/10 text-red-500 border border-red-500/20'
                                   : level >= 10 ? 'bg-orange-500/10 text-orange-500 border border-orange-500/20'
                                   : level >= 7  ? 'bg-blue-500/10 text-blue-500 border border-blue-500/20'
                                   : 'bg-green-500/10 text-green-500 border border-green-500/20';

                  return (
                    <tr
                      key={idx}
                      className="hover:bg-soc-dark/50 transition-colors cursor-pointer"
                      onClick={() => navigate(`/alerts?search=${alert.id}`)}
                    >
                      <td className="px-4 py-3 text-slate-400 whitespace-nowrap">
                        {new Date(alert.timestamp).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-slate-300 truncate max-w-[200px]" title={alert.rule_description}>
                        {alert.rule_description}
                      </td>
                      <td className="px-4 py-3 text-center">
                        <span className={clsx('px-2 py-0.5 rounded-full text-xs font-medium', levelColor)}>
                          L{level}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-slate-400">
                        {alert.src_ip || '-'}
                      </td>
                    </tr>
                  );
                }) : (
                  <tr>
                    <td colSpan="4" className="px-4 py-8 text-center text-slate-500">
                      No recent alerts found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>
  );
};

export default DashboardPage;
