// Filter dan pagination diproses API; penghapusan memakai pratinjau lalu konfirmasi admin.
import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Search,
  Filter,
  Download,
  ChevronLeft,
  ChevronRight,
  X,
  ShieldBan,
  Loader2,
  AlertCircle,
  Trash2
} from 'lucide-react';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';
import toast from 'react-hot-toast';
import clsx from 'clsx';

const formatRawAlert = (raw) => {
  if (!raw) return 'No raw data available';
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
};

const AlertsPage = () => {
  const { user } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [fetchingNew, setFetchingNew] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [purgeOpen, setPurgeOpen] = useState(false);
  const [purgePeriod, setPurgePeriod] = useState('week');
  const [purgePreview, setPurgePreview] = useState(null);
  const [purgePassword, setPurgePassword] = useState('');
  const [purgePhrase, setPurgePhrase] = useState('');
  const [purgeBusy, setPurgeBusy] = useState(false);
  const [purgeJob, setPurgeJob] = useState(null);

  // Pagination & Filters
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(25);
  const [totalPages, setTotalPages] = useState(1);
  const [totalItems, setTotalItems] = useState(0);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [threatFilter, setThreatFilter] = useState('All');

  const fetchAlertsData = async () => {
    setLoading(true);
    try {
      const params = {
        page,
        per_page: limit,
        search: search || undefined,
        threat_type: threatFilter === 'All' ? undefined : threatFilter,
        ...({
          Critical: { min_level: 12 },
          High: { min_level: 10, max_level: 11 },
          Medium: { min_level: 7, max_level: 9 },
          Low: { min_level: 0, max_level: 6 },
        }[severityFilter] || {})
      };

      const res = await api.getAlerts(params);
      setAlerts(res.data.items || []);
      setTotalPages(res.data.pages || 1);
      setTotalItems(res.data.total || 0);
    } catch (error) {
      console.error('Error fetching alerts:', error);
      toast.error('Failed to load alerts');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Delay slightly to prevent excessive requests while typing search
    const delayDebounceFn = setTimeout(() => {
      fetchAlertsData();
    }, 300);
    return () => clearTimeout(delayDebounceFn);
  }, [page, limit, search, severityFilter, threatFilter]);

  useEffect(() => {
    if (user?.role !== 'admin') return;
    api.getActiveAlertPurge().then((response) => {
      if (response.data.purge) setPurgeJob(response.data.purge);
    }).catch(() => {});
  }, [user?.role]);

  useEffect(() => {
    if (!purgeJob || !['starting', 'running'].includes(purgeJob.status)) return;
    const timer = setInterval(async () => {
      try {
        const response = await api.getAlertPurge(purgeJob.id);
        setPurgeJob(response.data);
        if (response.data.status === 'complete') {
          toast.success(`Penghapusan selesai: ${response.data.indexer_deleted} alert Indexer, ${response.data.soc_deleted} salinan SOC`);
          setSelectedAlert(null);
          setPage(1);
          fetchAlertsData();
        } else if (response.data.status === 'failed') {
          toast.error(response.data.error || 'Penghapusan gagal; periksa Audit Log');
        }
      } catch (error) {
        toast.error(error.response?.data?.message || 'Gagal membaca status penghapusan');
      }
    }, 5000);
    return () => clearInterval(timer);
  }, [purgeJob?.id, purgeJob?.status]);

  const previewPurge = async () => {
    setPurgeBusy(true);
    setPurgePreview(null);
    setPurgePassword('');
    setPurgePhrase('');
    try {
      const response = await api.previewAlertPurge(purgePeriod);
      setPurgePreview(response.data);
    } catch (error) {
      toast.error(error.response?.data?.message || 'Pratinjau gagal');
    } finally {
      setPurgeBusy(false);
    }
  };

  const confirmPurge = async () => {
    if (!purgePreview) return;
    setPurgeBusy(true);
    try {
      const response = await api.confirmAlertPurge(purgePreview.token, purgePassword, purgePhrase);
      setPurgeJob(response.data);
      setPurgePreview(null);
      setPurgePassword('');
      setPurgePhrase('');
      setPurgeOpen(false);
      toast.success('Penghapusan dimulai. Status akan diperbarui otomatis.');
    } catch (error) {
      toast.error(error.response?.data?.message || 'Konfirmasi gagal');
      if (error.response?.status !== 403) setPurgePreview(null);
    } finally {
      setPurgeBusy(false);
    }
  };

  useEffect(() => {
    const alertId = Number(searchParams.get('alert'));
    if (!Number.isInteger(alertId) || alertId <= 0) return;

    let active = true;
    api.getAlert(alertId)
      .then((response) => {
        if (active) setSelectedAlert(response.data);
      })
      .catch((error) => {
        console.error('Error opening notification alert:', error);
        if (active) toast.error('Alert details could not be loaded');
      });

    return () => {
      active = false;
    };
  }, [searchParams]);

  const closeAlertDetails = () => {
    setSelectedAlert(null);
    if (searchParams.has('alert')) {
      const nextParams = new URLSearchParams(searchParams);
      nextParams.delete('alert');
      setSearchParams(nextParams, { replace: true });
    }
  };

  const handleFetchNewAlerts = async () => {
    setFetchingNew(true);
    try {
      const response = await api.fetchAlerts();
      const summary = response.data.summary;
      toast.success(`Fetched ${response.data.fetched_count} alerts: ${summary.saved} new, ${summary.blocked} blocked, ${summary.block_failed || 0} block failed`);
      setPage(1);
      fetchAlertsData();
    } catch (error) {
      toast.error('Failed to fetch new alerts');
    } finally {
      setFetchingNew(false);
    }
  };

  const handleBlockIP = async (ip) => {
    if (!ip) return;
    try {
      await api.blockIP(ip, 'Blocked from Alert Details view');
      toast.success(`IP ${ip} blocked successfully`);
    } catch (error) {
      toast.error(error.response?.data?.message || `Failed to block IP ${ip}`);
    }
  };

  const getLevelColor = (level) => {
    if (level >= 12) return 'bg-red-500/10 text-red-500 border border-red-500/20';
    if (level >= 10) return 'bg-orange-500/10 text-orange-500 border border-orange-500/20';
    if (level >= 7) return 'bg-blue-500/10 text-blue-500 border border-blue-500/20';
    return 'bg-green-500/10 text-green-500 border border-green-500/20';
  };

  const getThreatColor = (threatType) => ({
    sql_injection: 'bg-fuchsia-500/10 text-fuchsia-300 border border-fuchsia-500/30',
    brute_force: 'bg-orange-500/10 text-orange-300 border border-orange-500/30',
    web_attack: 'bg-red-500/10 text-red-300 border border-red-500/30',
    web_defacement: 'bg-yellow-500/10 text-yellow-300 border border-yellow-500/30',
    webshell_content: 'bg-rose-500/10 text-rose-300 border border-rose-500/30',
    ip_reputation: 'bg-red-500/10 text-red-300 border border-red-500/30',
    host_command: 'bg-orange-500/10 text-orange-300 border border-orange-500/30',
    suspicious_process: 'bg-orange-500/10 text-orange-300 border border-orange-500/30',
    rootkit: 'bg-rose-500/10 text-rose-300 border border-rose-500/30',
    malware: 'bg-rose-500/10 text-rose-300 border border-rose-500/30',
    host_vulnerability: 'bg-yellow-500/10 text-yellow-300 border border-yellow-500/30',
  }[threatType] || 'bg-slate-500/10 text-slate-300 border border-slate-500/30');

  return (
    <div className="space-y-6 flex flex-col h-full">
      {/* Header & Toolbar */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Alerts Management</h1>
          <p className="text-sm text-slate-400">View and manage security alerts from Wazuh</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search description..."
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1); }}
              className="bg-soc-darker border border-soc-border rounded-lg pl-9 pr-3 py-2 text-sm text-white focus:border-soc-accent focus:ring-1 focus:ring-soc-accent w-64"
            />
          </div>
          <div className="relative">
            <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <select
              value={severityFilter}
              onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
              className="bg-soc-darker border border-soc-border rounded-lg pl-9 pr-8 py-2 text-sm text-white focus:border-soc-accent focus:ring-1 focus:ring-soc-accent appearance-none"
            >
              <option value="All">All Severities</option>
              <option value="Critical">Critical (12+)</option>
              <option value="High">High (10-11)</option>
              <option value="Medium">Medium (7-9)</option>
              <option value="Low">Low (&lt;7)</option>
            </select>
          </div>
          <div className="relative">
            <ShieldBan className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <select
              value={threatFilter}
              onChange={(e) => { setThreatFilter(e.target.value); setPage(1); }}
              className="bg-soc-darker border border-soc-border rounded-lg pl-9 pr-8 py-2 text-sm text-white focus:border-soc-accent focus:ring-1 focus:ring-soc-accent appearance-none"
            >
              <option value="All">All Attack Types</option>
              <option value="sql_injection">SQL Injection</option>
              <option value="brute_force">Brute Force</option>
              <option value="shellshock">Shellshock</option>
              <option value="webshell_probe">Webshell Probe</option>
              <option value="webshell_content">Possible Webshell File</option>
              <option value="wordpress_scan">WordPress Scan</option>
              <option value="vulnerability_scan">Vulnerability Scanner</option>
              <option value="sensitive_file">Sensitive File Access</option>
              <option value="rce">RCE / Command Injection</option>
              <option value="recon">Service Enumeration</option>
              <option value="path_traversal">Path Traversal / LFI</option>
              <option value="xss">XSS</option>
              <option value="ssrf">Possible SSRF</option>
              <option value="web_defacement">Web Defacement</option>
              <option value="ip_reputation">Known Bad IP</option>
              <option value="host_command">Suspicious Command</option>
              <option value="suspicious_process">Suspicious Process</option>
              <option value="rootkit">Rootcheck Finding</option>
              <option value="malware">Malware Reputation</option>
              <option value="host_vulnerability">Host Vulnerability</option>
            </select>
          </div>
          <button
            onClick={handleFetchNewAlerts}
            disabled={fetchingNew || ['starting', 'running'].includes(purgeJob?.status)}
            className="flex items-center gap-2 px-4 py-2 bg-soc-accent hover:bg-blue-600 disabled:bg-blue-800 disabled:opacity-70 text-white rounded-lg font-medium transition-colors text-sm"
          >
            {fetchingNew ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
            Fetch New Alerts
          </button>
          {user?.role === 'admin' && (
            <button
              onClick={() => { setPurgePreview(null); setPurgeOpen(true); }}
              disabled={['starting', 'running'].includes(purgeJob?.status)}
              className="flex items-center gap-2 px-4 py-2 bg-red-900/30 hover:bg-red-900/50 disabled:opacity-50 text-red-200 border border-red-700 rounded-lg font-medium text-sm"
            >
              <Trash2 className="h-4 w-4" /> Hapus alert lama
            </button>
          )}
        </div>
      </div>

      {user?.role === 'admin' && purgeJob && ['starting', 'running', 'failed'].includes(purgeJob.status) && (
        <div className="rounded-lg border border-soc-border bg-soc-card p-3 text-sm text-slate-200">
          Penghapusan alert: {purgeJob.status === 'failed' ? `perlu pemeriksaan — ${purgeJob.error}` : 'sedang diproses oleh Wazuh Indexer'}.
        </div>
      )}

      {purgeOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="w-full max-w-lg rounded-xl border border-soc-border bg-soc-card p-6 text-slate-200 shadow-2xl space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-bold text-white">Hapus riwayat alert Wazuh</h2>
              <button onClick={() => setPurgeOpen(false)} aria-label="Tutup"><X className="h-5 w-5" /></button>
            </div>
            <p className="text-sm text-slate-300">Pilih umur alert yang akan dihapus. Alert yang lebih baru tetap tersimpan. Operasi ini menghapus dokumen Indexer dan salinan SOC; riwayat blokir IP dan audit tetap ada.</p>
            <label className="block text-sm">
              <span className="block mb-1">Hapus alert yang lebih tua dari</span>
              <select value={purgePeriod} onChange={(event) => { setPurgePeriod(event.target.value); setPurgePreview(null); }} className="w-full rounded bg-soc-darker border border-soc-border p-2">
                <option value="week">1 minggu</option>
                <option value="month">1 bulan</option>
                <option value="six_months">6 bulan</option>
                <option value="year">1 tahun</option>
                <option value="all">Semua alert sampai sekarang</option>
              </select>
            </label>
            {!purgePreview ? (
              <button onClick={previewPurge} disabled={purgeBusy} className="rounded bg-soc-accent px-4 py-2 text-white disabled:opacity-50">{purgeBusy ? 'Menghitung…' : 'Tahap 1: Lihat pratinjau'}</button>
            ) : (
              <div className="space-y-3 rounded border border-red-800 bg-red-950/20 p-4">
                <p className="font-semibold">Akan dihapus: {purgePreview.indexer_count} dokumen Indexer dan {purgePreview.soc_count} salinan SOC.</p>
                <p className="text-sm">Batas waktu: sebelum {new Date(purgePreview.to_utc).toLocaleString('id-ID')}. Pratinjau berlaku 5 menit. Bila jumlah berubah, buat pratinjau baru.</p>
                <p className="text-xs text-slate-400">File alert mentah Wazuh Manager tidak terhapus dari tindakan ini. Pengosongan ruang Indexer mungkin tidak langsung terlihat.</p>
                <label className="block text-sm">Password akun admin
                  <input type="password" autoComplete="current-password" value={purgePassword} onChange={(event) => setPurgePassword(event.target.value)} className="mt-1 w-full rounded bg-soc-darker border border-soc-border p-2" />
                </label>
                <label className="block text-sm">Ketik persis <strong>{purgePreview.confirmation_phrase}</strong>
                  <input value={purgePhrase} onChange={(event) => setPurgePhrase(event.target.value)} className="mt-1 w-full rounded bg-soc-darker border border-soc-border p-2" />
                </label>
                <button onClick={confirmPurge} disabled={purgeBusy || !purgePassword || purgePhrase !== purgePreview.confirmation_phrase} className="rounded bg-red-700 px-4 py-2 font-semibold text-white disabled:opacity-50">Tahap 2: Hapus permanen</button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex-1 bg-soc-card rounded-xl border border-soc-border overflow-hidden flex flex-col relative">

        {loading && !alerts.length ? (
          <div className="flex-1 flex items-center justify-center text-slate-400">
            <Loader2 className="h-8 w-8 animate-spin text-soc-accent" />
          </div>
        ) : alerts.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center text-slate-400 p-8">
            <AlertCircle className="h-12 w-12 mb-4 text-slate-500" />
            <h3 className="text-lg font-medium text-slate-300">No alerts found</h3>
            <p className="text-sm">Try adjusting your search or filters.</p>
          </div>
        ) : (
          <div className="overflow-x-auto flex-1">
            <table className="w-full text-sm text-left">
              <thead className="text-xs text-slate-400 uppercase bg-soc-dark/80 border-b border-soc-border sticky top-0 z-10">
                <tr>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">Rule ID</th>
                  <th className="px-4 py-3">Description</th>
                  <th className="px-4 py-3">Attack Type</th>
                  <th className="px-4 py-3 text-center">Level</th>
                  <th className="px-4 py-3">Source IP</th>
                  <th className="px-4 py-3">Agent</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border">
                {alerts.map((alert) => (
                  <tr
                    key={alert.id}
                    onClick={() => setSelectedAlert(alert)}
                    className="hover:bg-soc-dark/50 transition-colors cursor-pointer"
                  >
                    <td className="px-4 py-3 text-slate-300 whitespace-nowrap">
                      {new Date(alert.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-slate-400 font-mono text-xs">{alert.rule_id}</td>
                    <td className="px-4 py-3 text-slate-200">{alert.rule_description}</td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className={clsx('px-2 py-0.5 rounded-full text-xs font-medium', getThreatColor(alert.threat_type))}>
                        {alert.threat_label || 'Other'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-center">
                      <span className={clsx('px-2 py-0.5 rounded-full text-xs font-medium', getLevelColor(alert.rule_level))}>
                        L{alert.rule_level}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-300">{alert.src_ip || '-'}</td>
                    <td className="px-4 py-3 text-slate-400">{alert.agent_name || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Footer */}
        <div className="border-t border-soc-border bg-soc-dark/50 p-4 flex items-center justify-between">
          <div className="text-sm text-slate-400">
            Showing <span className="font-medium text-slate-200">{alerts.length > 0 ? (page - 1) * limit + 1 : 0}</span> to <span className="font-medium text-slate-200">{Math.min(page * limit, totalItems)}</span> of <span className="font-medium text-slate-200">{totalItems}</span> results
          </div>
          <div className="flex items-center gap-2">
            <select
              value={limit}
              onChange={(e) => { setLimit(Number(e.target.value)); setPage(1); }}
              className="bg-soc-darker border border-soc-border rounded px-2 py-1 text-sm text-slate-300 mr-2"
            >
              <option value="10">10 / page</option>
              <option value="25">25 / page</option>
              <option value="50">50 / page</option>
              <option value="100">100 / page</option>
            </select>
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="p-1 rounded bg-soc-card border border-soc-border text-slate-400 hover:text-white disabled:opacity-50"
            >
              <ChevronLeft className="h-5 w-5" />
            </button>
            <span className="text-sm text-slate-300 px-2">Page {page} of {totalPages}</span>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page === totalPages || totalPages === 0}
              className="p-1 rounded bg-soc-card border border-soc-border text-slate-400 hover:text-white disabled:opacity-50"
            >
              <ChevronRight className="h-5 w-5" />
            </button>
          </div>
        </div>
      </div>

      {/* Alert Detail Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-soc-card border border-soc-border rounded-xl shadow-2xl w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden">

            {/* Modal Header */}
            <div className="flex items-center justify-between p-5 border-b border-soc-border bg-soc-darker/50">
              <div className="flex items-center gap-3">
                <span className={clsx('px-2 py-1 rounded text-sm font-bold', getLevelColor(selectedAlert.rule_level))}>
                  Level {selectedAlert.rule_level}
                </span>
                <h2 className="text-lg font-bold text-white">Alert Details</h2>
              </div>
              <button
                onClick={closeAlertDetails}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-soc-border transition-colors"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6">

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">Rule Description</h3>
                  <p className="text-base text-slate-200">{selectedAlert.rule_description}</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">Timestamp</h3>
                  <p className="text-base text-slate-200">{new Date(selectedAlert.timestamp).toLocaleString()}</p>
                </div>

                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">Rule ID</h3>
                  <p className="text-base font-mono text-slate-200">{selectedAlert.rule_id}</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">Agent</h3>
                  <p className="text-base text-slate-200">{selectedAlert.agent_name || 'N/A'} ({selectedAlert.agent_id || '-'})</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">Auto-response</h3>
                  <p className="text-base text-slate-200">{selectedAlert.action_taken || (selectedAlert.is_processed ? 'No action recorded' : 'Not processed')}</p>
                </div>

                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">Attack Type</h3>
                  <span className={clsx('inline-flex px-2 py-1 rounded text-sm font-medium', getThreatColor(selectedAlert.threat_type))}>
                    {selectedAlert.threat_label || 'Other'}
                  </span>
                </div>

                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">Source IP</h3>
                  <div className="flex items-center gap-3">
                    <p className="text-base text-slate-200">{selectedAlert.src_ip || 'N/A'}</p>
                    {selectedAlert.src_ip && (
                      <button
                        onClick={() => handleBlockIP(selectedAlert.src_ip)}
                        className="flex items-center gap-1 px-2 py-1 bg-soc-danger/10 hover:bg-soc-danger/20 text-soc-danger border border-soc-danger/20 rounded text-xs font-medium transition-colors"
                      >
                        <ShieldBan className="h-3 w-3" />
                        Block IP
                      </button>
                    )}
                  </div>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">Affected asset</h3>
                  <p className="text-base text-slate-200">{selectedAlert.asset_name || selectedAlert.agent_name || 'Unknown'}{selectedAlert.domain ? ` (${selectedAlert.domain})` : ''}</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">Target endpoint / file</h3>
                  <p className="break-all font-mono text-sm text-slate-200">{selectedAlert.target || 'Not available in this alert'}</p>
                </div>
              </div>

              <div className="rounded-lg border border-soc-accent/20 bg-soc-darker p-4">
                <h3 className="text-sm font-semibold text-white">Recommended response</h3>
                <p className="mt-2 text-sm text-slate-300">{selectedAlert.mitigation_tip}</p>
                <p className="mt-2 text-xs text-slate-400">{selectedAlert.auto_block_eligible ? 'IP blocking is possible when the alert level, IP, age, and whitelist checks pass.' : 'This alert needs investigation; STIS SOC will not auto-block an inferred IP.'}</p>
                {selectedAlert.log_source && <p className="mt-2 break-all text-xs text-slate-400">Log source: {selectedAlert.log_source}</p>}
              </div>

              {/* Raw JSON viewer */}
              <div>
                <h3 className="text-sm font-medium text-slate-400 mb-2">Raw Alert Data</h3>
                <div className="bg-soc-darker border border-soc-border rounded-lg p-4 overflow-x-auto">
                  <pre className="text-xs font-mono text-slate-300">
                    {formatRawAlert(selectedAlert.raw_json)}
                  </pre>
                </div>
              </div>

            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-soc-border bg-soc-darker/50 flex justify-end">
              <button
                onClick={closeAlertDetails}
                className="px-4 py-2 bg-soc-border hover:bg-slate-600 text-white rounded-lg font-medium transition-colors text-sm"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AlertsPage;
