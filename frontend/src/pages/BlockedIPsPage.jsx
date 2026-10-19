// Pisahkan perubahan alias firewall dari penghapusan riwayat IP yang sudah unblocked.
import React, { useState, useEffect } from 'react';
import {
  ShieldBan,
  Search,
  Filter,
  RefreshCw,
  Plus,
  Unlock,
  Trash2,
  Loader2,
  X,
  AlertCircle
} from 'lucide-react';
import api from '../services/api';
import toast from 'react-hot-toast';
import clsx from 'clsx';

const BlockedIPsPage = () => {
  const [blockedIps, setBlockedIps] = useState([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);

  // Pagination & Filters
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(25);
  const [totalPages, setTotalPages] = useState(1);
  const [totalItems, setTotalItems] = useState(0);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('All');
  const [selectedIds, setSelectedIds] = useState([]);
  const [selectedRecord, setSelectedRecord] = useState(null);

  // Modal State
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [blockForm, setBlockForm] = useState({ ip: '', reason: '' });
  const [submitting, setSubmitting] = useState(false);

  const fetchBlockedIPs = async () => {
    setLoading(true);
    try {
      const params = {
        page,
        per_page: limit,
        search: search || undefined,
        status: statusFilter !== 'All' ? statusFilter : undefined
      };

      const res = await api.getBlockedIPs(params);
      setBlockedIps(res.data.items || []);
      setSelectedIds([]);
      setTotalPages(res.data.pages || 1);
      setTotalItems(res.data.total || 0);
    } catch (error) {
      console.error('Error fetching blocked IPs:', error);
      toast.error('Failed to load blocked IPs');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const delayDebounceFn = setTimeout(() => {
      fetchBlockedIPs();
    }, 300);
    return () => clearTimeout(delayDebounceFn);
  }, [page, limit, search, statusFilter]);

  const handleSync = async () => {
    setSyncing(true);
    try {
      const response = await api.syncBlockedIPs();
      toast.success(`Synced with pfSense: ${response.data.imported} imported, ${response.data.marked_unblocked} marked unblocked`);
      fetchBlockedIPs();
    } catch (error) {
      toast.error(error.response?.data?.message || 'Failed to synchronize with pfSense');
    } finally {
      setSyncing(false);
    }
  };

  const handleBlockIP = async (e) => {
    e.preventDefault();
    const ipAddress = blockForm.ip.trim();
    const reason = blockForm.reason.trim();
    if (!ipAddress || !reason) return toast.error('IP address and reason are required');

    setSubmitting(true);
    try {
      await api.blockIP(ipAddress, reason);
      toast.success(`IP ${ipAddress} blocked successfully`);
      setIsModalOpen(false);
      setBlockForm({ ip: '', reason: '' });
      fetchBlockedIPs();
    } catch (error) {
      toast.error(error.response?.data?.message || `Failed to block IP ${ipAddress}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleUnblockIP = async (record) => {
    if (!window.confirm(`Are you sure you want to unblock ${record.ip_address}?`)) return;

    try {
      await api.unblockIP(record.id);
      toast.success(`IP ${record.ip_address} unblocked successfully`);
      setSelectedRecord(null);
      fetchBlockedIPs();
    } catch (error) {
      toast.error(error.response?.data?.message || `Failed to unblock IP ${record.ip_address}`);
    }
  };

  const handleReblockIP = async (record) => {
    try {
      await api.reblockIP(record.id);
      toast.success(`IP ${record.ip_address} blocked again`);
      setSelectedRecord(null);
      fetchBlockedIPs();
    } catch (error) {
      toast.error(error.response?.data?.message || `Failed to block IP ${record.ip_address}`);
    }
  };

  const toggleSelected = (id) => {
    setSelectedIds(ids => ids.includes(id) ? ids.filter(value => value !== id) : [...ids, id]);
  };

  const visibleUnblockedIds = blockedIps.filter(record => record.status === 'unblocked').map(record => record.id);
  const allVisibleUnblockedSelected = visibleUnblockedIds.length > 0 && visibleUnblockedIds.every(id => selectedIds.includes(id));

  const handleDeleteSelected = async () => {
    if (!selectedIds.length || !window.confirm(`Delete ${selectedIds.length} selected unblocked history records?`)) return;
    try {
      const response = await api.deleteUnblockedHistory(selectedIds);
      toast.success(response.data.message);
      setSelectedIds([]);
      if (blockedIps.length === selectedIds.length && page > 1) setPage(page - 1);
      else fetchBlockedIPs();
    } catch (error) {
      toast.error(error.response?.data?.message || 'Failed to delete selected history');
    }
  };

  const formatDateTime = (value) => value ? new Date(value).toLocaleString() : '-';

  return (
    <div className="space-y-6 flex flex-col h-full">
      {/* Header & Toolbar */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Blocked IPs Management</h1>
          <p className="text-sm text-slate-400">Manage IP addresses blocked in pfSense firewall</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search IP..."
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1); }}
              className="bg-soc-darker border border-soc-border rounded-lg pl-9 pr-3 py-2 text-sm text-white focus:border-soc-accent focus:ring-1 focus:ring-soc-accent w-48"
            />
          </div>
          <div className="relative">
            <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <select
              value={statusFilter}
              onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
              className="bg-soc-darker border border-soc-border rounded-lg pl-9 pr-8 py-2 text-sm text-white focus:border-soc-accent focus:ring-1 focus:ring-soc-accent appearance-none"
            >
              <option value="All">All Statuses</option>
              <option value="blocked">Blocked</option>
              <option value="unblocked">Unblocked</option>
            </select>
          </div>
          <button
            onClick={handleSync}
            disabled={syncing}
            className="flex items-center gap-2 px-4 py-2 bg-soc-border hover:bg-slate-600 disabled:opacity-70 text-white rounded-lg font-medium transition-colors text-sm"
          >
            <RefreshCw className={clsx('h-4 w-4', syncing && 'animate-spin')} />
            Sync
          </button>
          <button
            onClick={() => setIsModalOpen(true)}
            className="flex items-center gap-2 px-4 py-2 bg-soc-danger hover:bg-red-600 text-white rounded-lg font-medium transition-colors text-sm"
          >
            <Plus className="h-4 w-4" />
            Block IP
          </button>
        </div>
      </div>

      {selectedIds.length > 0 && (
        <div className="flex items-center justify-between gap-3 rounded-lg border border-soc-border bg-soc-card px-4 py-3 text-sm text-slate-300">
          <span>{selectedIds.length} unblocked records selected</span>
          <button onClick={handleDeleteSelected} className="inline-flex items-center gap-2 rounded bg-soc-danger px-3 py-2 font-medium text-white hover:bg-red-600">
            <Trash2 className="h-4 w-4" /> Delete selected
          </button>
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex-1 bg-soc-card rounded-xl border border-soc-border overflow-hidden flex flex-col relative">

        {loading ? (
          <div className="flex-1 flex items-center justify-center text-slate-400">
            <Loader2 className="h-8 w-8 animate-spin text-soc-accent" />
          </div>
        ) : blockedIps.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center text-slate-400 p-8">
            <ShieldBan className="h-12 w-12 mb-4 text-slate-500" />
            <h3 className="text-lg font-medium text-slate-300">No blocked IPs found</h3>
            <p className="text-sm">No IP addresses matching your criteria are currently recorded.</p>
          </div>
        ) : (
          <div className="overflow-x-auto flex-1">
            <table className="w-full text-sm text-left">
              <thead className="text-xs text-slate-400 uppercase bg-soc-dark/80 border-b border-soc-border sticky top-0">
                <tr>
                  <th className="px-4 py-3">
                    <input type="checkbox" aria-label="Select all unblocked records on this page"
                      checked={allVisibleUnblockedSelected}
                      disabled={visibleUnblockedIds.length === 0}
                      onChange={() => setSelectedIds(allVisibleUnblockedSelected ? [] : visibleUnblockedIds)} />
                  </th>
                  <th className="px-4 py-3">IP Address</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Source</th>
                  <th className="px-4 py-3">Reason</th>
                  <th className="px-4 py-3">Blocked At</th>
                  <th className="px-4 py-3">Blocked By</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border">
                {blockedIps.map((record) => (
                  <tr
                    key={record.id}
                    role="button"
                    tabIndex={0}
                    aria-label={`View details for ${record.ip_address}`}
                    onClick={() => setSelectedRecord(record)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        setSelectedRecord(record);
                      }
                    }}
                    className="hover:bg-soc-dark/50 transition-colors cursor-pointer focus:outline-none focus:bg-soc-dark/70"
                  >
                    <td
                      className="px-4 py-3"
                      onClick={(event) => event.stopPropagation()}
                      onKeyDown={(event) => event.stopPropagation()}
                    >
                      {record.status === 'unblocked' && (
                        <input type="checkbox" aria-label={`Select unblocked record ${record.ip_address}`}
                          checked={selectedIds.includes(record.id)} onChange={() => toggleSelected(record.id)} />
                      )}
                    </td>
                    <td className="px-4 py-3 font-medium text-slate-200">{record.ip_address}</td>
                    <td className="px-4 py-3">
                      <span className={clsx(
                        'px-2 py-0.5 rounded-full text-xs font-medium',
                        record.status === 'blocked' ? 'bg-red-500/10 text-red-500 border border-red-500/20' : 'bg-green-500/10 text-green-500 border border-green-500/20'
                      )}>
                        {record.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={clsx(
                        'px-2 py-0.5 rounded-full text-xs font-medium',
                        record.source === 'auto' ? 'bg-purple-500/10 text-purple-400' : 'bg-blue-500/10 text-blue-400'
                      )}>
                        {record.source}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-300 max-w-xs truncate" title={record.reason}>{record.reason || '-'}</td>
                    <td className="px-4 py-3 text-slate-400">
                      {formatDateTime(record.blocked_at)}
                    </td>
                    <td className="px-4 py-3 text-slate-400">{record.blocked_by || 'System'}</td>
                    <td
                      className="px-4 py-3 text-right"
                      onClick={(event) => event.stopPropagation()}
                      onKeyDown={(event) => event.stopPropagation()}
                    >
                      {record.status === 'blocked' ? (
                        <button
                          onClick={() => handleUnblockIP(record)}
                          className="inline-flex items-center gap-1 px-3 py-1 bg-soc-success/10 hover:bg-soc-success/20 text-soc-success rounded text-xs font-medium transition-colors"
                        >
                          <Unlock className="h-3 w-3" />
                          Unblock
                        </button>
                      ) : (
                        <button onClick={() => handleReblockIP(record)}
                          className="inline-flex items-center gap-1 px-3 py-1 bg-soc-danger/10 hover:bg-soc-danger/20 text-soc-danger rounded text-xs font-medium transition-colors">
                          <ShieldBan className="h-3 w-3" /> Block again
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Footer */}
        <div className="border-t border-soc-border bg-soc-dark/50 p-4 flex items-center justify-between">
          <div className="text-sm text-slate-400">
            Showing <span className="font-medium text-slate-200">{blockedIps.length > 0 ? (page - 1) * limit + 1 : 0}</span> to <span className="font-medium text-slate-200">{Math.min(page * limit, totalItems)}</span> of <span className="font-medium text-slate-200">{totalItems}</span> results
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="px-3 py-1 rounded bg-soc-card border border-soc-border text-slate-400 hover:text-white disabled:opacity-50 text-sm"
            >
              Prev
            </button>
            <span className="text-sm text-slate-300 px-2">Page {page} of {totalPages}</span>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page === totalPages || totalPages === 0}
              className="px-3 py-1 rounded bg-soc-card border border-soc-border text-slate-400 hover:text-white disabled:opacity-50 text-sm"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Blocked IP Detail Modal */}
      {selectedRecord && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-soc-card border border-soc-border rounded-xl shadow-2xl w-full max-w-3xl max-h-[90vh] flex flex-col overflow-hidden">
            <div className="flex items-center justify-between p-5 border-b border-soc-border bg-soc-darker/50">
              <div className="flex items-center gap-3">
                <ShieldBan className="h-5 w-5 text-soc-danger" />
                <h2 className="text-lg font-bold text-white">Blocked IP Details</h2>
                <span className={clsx(
                  'px-2 py-1 rounded text-xs font-medium',
                  selectedRecord.status === 'blocked'
                    ? 'bg-red-500/10 text-red-500 border border-red-500/20'
                    : 'bg-green-500/10 text-green-500 border border-green-500/20'
                )}>
                  {(selectedRecord.status || 'unknown').toUpperCase()}
                </span>
              </div>
              <button
                onClick={() => setSelectedRecord(null)}
                aria-label="Close blocked IP details"
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-soc-border transition-colors"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">IP Address</h3>
                  <p className="text-base font-mono text-slate-200">{selectedRecord.ip_address}</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">Source</h3>
                  <p className="text-base text-slate-200">{selectedRecord.source || '-'}</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">Blocked At</h3>
                  <p className="text-base text-slate-200">{formatDateTime(selectedRecord.blocked_at)}</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">Blocked By</h3>
                  <p className="text-base text-slate-200">{selectedRecord.blocked_by || 'System'}</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">Unblocked At</h3>
                  <p className="text-base text-slate-200">{formatDateTime(selectedRecord.unblocked_at)}</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">Unblocked By</h3>
                  <p className="text-base text-slate-200">{selectedRecord.unblocked_by || '-'}</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">Related Alert ID</h3>
                  <p className="text-base font-mono text-slate-200">{selectedRecord.alert_id || '-'}</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">pfSense Rule ID</h3>
                  <p className="text-base font-mono text-slate-200 break-all">{selectedRecord.pfsense_rule_id || '-'}</p>
                </div>
              </div>

              <div>
                <h3 className="text-sm font-medium text-slate-400 mb-2">Reason</h3>
                <div className="bg-soc-darker border border-soc-border rounded-lg p-4 text-sm text-slate-200 whitespace-pre-wrap break-words">
                  {selectedRecord.reason || '-'}
                </div>
              </div>
            </div>

            <div className="p-4 border-t border-soc-border bg-soc-darker/50 flex flex-wrap justify-end gap-3">
              {selectedRecord.status === 'blocked' ? (
                <button
                  onClick={() => handleUnblockIP(selectedRecord)}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-soc-success/10 hover:bg-soc-success/20 text-soc-success rounded-lg font-medium transition-colors text-sm"
                >
                  <Unlock className="h-4 w-4" /> Unblock
                </button>
              ) : (
                <button
                  onClick={() => handleReblockIP(selectedRecord)}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-soc-danger/10 hover:bg-soc-danger/20 text-soc-danger rounded-lg font-medium transition-colors text-sm"
                >
                  <ShieldBan className="h-4 w-4" /> Block again
                </button>
              )}
              <button
                onClick={() => setSelectedRecord(null)}
                className="px-4 py-2 bg-soc-border hover:bg-slate-600 text-white rounded-lg font-medium transition-colors text-sm"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Block IP Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-soc-card border border-soc-border rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
            <div className="flex items-center justify-between p-5 border-b border-soc-border bg-soc-darker/50">
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <ShieldBan className="h-5 w-5 text-soc-danger" />
                Manually Block IP
              </h2>
              <button
                onClick={() => setIsModalOpen(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-soc-border transition-colors"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleBlockIP} className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">IP Address *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 192.168.18.103"
                  value={blockForm.ip}
                  onChange={(e) => setBlockForm({...blockForm, ip: e.target.value})}
                  className="w-full bg-soc-darker border border-soc-border rounded-lg px-3 py-2 text-white focus:border-soc-accent focus:ring-1 focus:ring-soc-accent"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Reason *</label>
                <textarea
                  required
                  placeholder="Why is this IP being blocked?"
                  value={blockForm.reason}
                  onChange={(e) => setBlockForm({...blockForm, reason: e.target.value})}
                  className="w-full bg-soc-darker border border-soc-border rounded-lg px-3 py-2 text-white focus:border-soc-accent focus:ring-1 focus:ring-soc-accent h-24 resize-none"
                />
              </div>

              <div className="flex justify-end gap-3 pt-4">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 bg-soc-border hover:bg-slate-600 text-white rounded-lg font-medium transition-colors text-sm"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="flex items-center gap-2 px-4 py-2 bg-soc-danger hover:bg-red-600 disabled:bg-red-800 disabled:opacity-70 text-white rounded-lg font-medium transition-colors text-sm"
                >
                  {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldBan className="h-4 w-4" />}
                  Block IP
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default BlockedIPsPage;
