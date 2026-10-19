// Sajikan jejak tindakan dan hasilnya untuk pemeriksaan operator.
import React, { useState, useEffect } from 'react';
import {
  Search,
  Filter,
  Loader2,
  Clock,
  Eye,
  X
} from 'lucide-react';
import api from '../services/api';
import toast from 'react-hot-toast';
import clsx from 'clsx';

const AuditPage = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedLog, setSelectedLog] = useState(null);

  // Pagination & Filters
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(25);
  const [totalPages, setTotalPages] = useState(1);
  const [totalItems, setTotalItems] = useState(0);
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('All');

  const fetchAuditLogs = async () => {
    setLoading(true);
    try {
      const params = {
        page,
        per_page: limit,
        search: search || undefined,
        action: actionFilter !== 'All' ? actionFilter : undefined
      };

      const res = await api.getAuditLogs(params);
      setLogs(res.data.items || []);
      setTotalPages(res.data.pages || 1);
      setTotalItems(res.data.total || 0);
    } catch (error) {
      console.error('Error fetching audit logs:', error);
      toast.error('Failed to load audit logs');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const delayDebounceFn = setTimeout(() => {
      fetchAuditLogs();
    }, 300);
    return () => clearTimeout(delayDebounceFn);
  }, [page, limit, search, actionFilter]);

  const getActionColor = (action) => {
    switch(action) {
      case 'login': return 'bg-blue-500/10 text-blue-400 border border-blue-500/20';
      case 'logout': return 'bg-slate-500/10 text-slate-400 border border-slate-500/20';
      case 'block_ip': return 'bg-red-500/10 text-red-500 border border-red-500/20';
      case 'unblock_ip': return 'bg-green-500/10 text-green-500 border border-green-500/20';
      case 'config_change': return 'bg-orange-500/10 text-orange-400 border border-orange-500/20';
      case 'fetch_alerts': return 'bg-purple-500/10 text-purple-400 border border-purple-500/20';
      case 'test_connection': return 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20';
      default: return 'bg-slate-500/10 text-slate-300 border border-slate-500/20';
    }
  };

  const formatDateTime = (value) => value ? new Date(value).toLocaleString() : '-';

  return (
    <div className="space-y-6 flex flex-col h-full">
      {/* Header & Toolbar */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">System Audit Logs</h1>
          <p className="text-sm text-slate-400">Track user actions and system events</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search details or user..."
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1); }}
              className="bg-soc-darker border border-soc-border rounded-lg pl-9 pr-3 py-2 text-sm text-white focus:border-soc-accent focus:ring-1 focus:ring-soc-accent w-56"
            />
          </div>
          <div className="relative">
            <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <select
              value={actionFilter}
              onChange={(e) => { setActionFilter(e.target.value); setPage(1); }}
              className="bg-soc-darker border border-soc-border rounded-lg pl-9 pr-8 py-2 text-sm text-white focus:border-soc-accent focus:ring-1 focus:ring-soc-accent appearance-none"
            >
              <option value="All">All Actions</option>
              <option value="login">Login</option>
              <option value="logout">Logout</option>
              <option value="block_ip">Block IP</option>
              <option value="unblock_ip">Unblock IP</option>
              <option value="config_change">Config Change</option>
              <option value="fetch_alerts">Fetch Alerts</option>
              <option value="test_connection">Test Connection</option>
            </select>
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 bg-soc-card rounded-xl border border-soc-border overflow-hidden flex flex-col relative">

        {loading ? (
          <div className="flex-1 flex items-center justify-center text-slate-400">
            <Loader2 className="h-8 w-8 animate-spin text-soc-accent" />
          </div>
        ) : logs.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center text-slate-400 p-8">
            <Clock className="h-12 w-12 mb-4 text-slate-500" />
            <h3 className="text-lg font-medium text-slate-300">No audit logs found</h3>
            <p className="text-sm">No activity records match your current filters.</p>
          </div>
        ) : (
          <div className="overflow-x-auto flex-1">
            <table className="w-full text-sm text-left">
              <thead className="text-xs text-slate-400 uppercase bg-soc-dark/80 border-b border-soc-border sticky top-0">
                <tr>
                  <th className="px-4 py-3 w-48">Timestamp</th>
                  <th className="px-4 py-3 w-40">Action</th>
                  <th className="px-4 py-3">Details</th>
                  <th className="px-4 py-3 w-32">User</th>
                  <th className="px-4 py-3 w-32">IP Address</th>
                  <th className="px-4 py-3 w-28 text-center">Result</th>
                  <th className="px-4 py-3 w-12"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border">
                {logs.map((log) => (
                    <tr
                      key={log.id}
                      role="button"
                      tabIndex={0}
                      aria-label={`View audit log ${log.id} details`}
                      onClick={() => setSelectedLog(log)}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault();
                          setSelectedLog(log);
                        }
                      }}
                      className="hover:bg-soc-dark/50 transition-colors cursor-pointer focus:outline-none focus:bg-soc-dark/70"
                    >
                      <td className="px-4 py-3 text-slate-300 whitespace-nowrap">
                        {formatDateTime(log.created_at)}
                      </td>
                      <td className="px-4 py-3">
                        <span className={clsx('px-2 py-0.5 rounded-full text-xs font-medium', getActionColor(log.action))}>
                          {log.action}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-slate-300 truncate max-w-sm">
                        {log.details || '-'}
                      </td>
                      <td className="px-4 py-3 text-slate-400">{log.performed_by || 'System'}</td>
                      <td className="px-4 py-3 text-slate-400">{log.ip_address || '-'}</td>
                      <td className="px-4 py-3 text-center">
                        <span className={clsx(
                          'px-2 py-0.5 rounded-full text-xs font-medium',
                          log.result === 'success' ? 'bg-green-500/10 text-green-500' : 'bg-red-500/10 text-red-500'
                        )}>
                          {(log.result || 'unknown').toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Eye className="h-4 w-4 ml-auto text-slate-500" aria-hidden="true" />
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
            Showing <span className="font-medium text-slate-200">{logs.length > 0 ? (page - 1) * limit + 1 : 0}</span> to <span className="font-medium text-slate-200">{Math.min(page * limit, totalItems)}</span> of <span className="font-medium text-slate-200">{totalItems}</span> results
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

      {/* Audit Log Detail Modal */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-soc-card border border-soc-border rounded-xl shadow-2xl w-full max-w-3xl max-h-[90vh] flex flex-col overflow-hidden">
            <div className="flex items-center justify-between p-5 border-b border-soc-border bg-soc-darker/50">
              <div className="flex items-center gap-3">
                <Clock className="h-5 w-5 text-soc-accent" />
                <h2 className="text-lg font-bold text-white">Audit Log Details</h2>
                <span className={clsx('px-2 py-1 rounded text-xs font-medium', getActionColor(selectedLog.action))}>
                  {selectedLog.action || 'unknown'}
                </span>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                aria-label="Close audit log details"
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-soc-border transition-colors"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">Timestamp</h3>
                  <p className="text-base text-slate-200">{formatDateTime(selectedLog.created_at)}</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">Result</h3>
                  <span className={clsx(
                    'inline-flex px-2 py-1 rounded text-sm font-medium',
                    selectedLog.result === 'success'
                      ? 'bg-green-500/10 text-green-500 border border-green-500/20'
                      : 'bg-red-500/10 text-red-500 border border-red-500/20'
                  )}>
                    {(selectedLog.result || 'unknown').toUpperCase()}
                  </span>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">Performed By</h3>
                  <p className="text-base text-slate-200">{selectedLog.performed_by || 'System'}</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">IP Address</h3>
                  <p className="text-base font-mono text-slate-200">{selectedLog.ip_address || '-'}</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">Audit ID</h3>
                  <p className="text-base font-mono text-slate-200">{selectedLog.id}</p>
                </div>
              </div>

              <div>
                <h3 className="text-sm font-medium text-slate-400 mb-2">Details</h3>
                <div className="bg-soc-darker border border-soc-border rounded-lg p-4 text-sm text-slate-200 whitespace-pre-wrap break-words">
                  {selectedLog.details || '-'}
                </div>
              </div>

              {selectedLog.error_message && (
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-2">Error Details</h3>
                  <div className="bg-soc-darker border border-soc-danger/30 rounded-lg p-4 text-sm font-mono text-soc-danger/90 whitespace-pre-wrap break-words">
                    {selectedLog.error_message}
                  </div>
                </div>
              )}
            </div>

            <div className="p-4 border-t border-soc-border bg-soc-darker/50 flex justify-end">
              <button
                onClick={() => setSelectedLog(null)}
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

export default AuditPage;
