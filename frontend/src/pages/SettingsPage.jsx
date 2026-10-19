// Konversi nilai konfigurasi untuk formulir; secret kosong dapat berarti nilai lama dipertahankan.
import React, { useState, useEffect } from 'react';
import {
  Save,
  Settings,
  Server,
  ShieldCheck,
  Zap,
  Eye,
  EyeOff,
  Loader2,
  CheckCircle2,
  XCircle
} from 'lucide-react';
import api from '../services/api';
import toast from 'react-hot-toast';

const SettingsPage = () => {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testingWazuh, setTestingWazuh] = useState(false);
  const [testingPfSense, setTestingPfSense] = useState(false);
  const [autoStatus, setAutoStatus] = useState(null);

  // UI states for passwords
  const [showWazuhApiPwd, setShowWazuhApiPwd] = useState(false);
  const [showWazuhIdxPwd, setShowWazuhIdxPwd] = useState(false);
  const [showPfSenseKey, setShowPfSenseKey] = useState(false);

  // Settings Form State
  const [config, setConfig] = useState({
    wazuh_host: '',
    wazuh_api_port: '',
    wazuh_indexer_port: '',
    wazuh_api_user: '',
    wazuh_api_password: '',
    wazuh_indexer_user: '',
    wazuh_indexer_password: '',
    pfsense_host: '',
    pfsense_api_key: '',
    pfsense_block_interface: '',
    pfsense_alias_name: '',
    auto_response_enabled: false,
    alert_threshold_level: 10,
    polling_interval_seconds: 60,
    auto_response_max_alert_age_seconds: 600,
    whitelist_ips: ''
  });

  useEffect(() => {
    fetchSettings();
    fetchAutoStatus();
  }, []);

  const fetchAutoStatus = async () => {
    try {
      const res = await api.getAutoResponseStatus();
      setAutoStatus(res.data);
    } catch (error) {
      console.error('Error fetching auto-response status:', error);
    }
  };

  const fetchSettings = async () => {
    try {
      const res = await api.getSettings();
      if (res.data) {
        // Ensure numbers are properly set and handle nulls
        const fetched = res.data;
        setConfig({
          ...config,
          ...fetched,
          auto_response_enabled: String(fetched.auto_response_enabled).toLowerCase() === 'true',
          alert_threshold_level: fetched.alert_threshold_level || 10,
          polling_interval_seconds: fetched.polling_interval_seconds || 60,
          auto_response_max_alert_age_seconds: fetched.auto_response_max_alert_age_seconds || 600,
          whitelist_ips: Array.isArray(fetched.whitelist_ips)
            ? fetched.whitelist_ips.join(', ')
            : (fetched.whitelist_ips || '')
        });
      }
    } catch (error) {
      console.error('Error fetching settings:', error);
      toast.error('Failed to load settings');
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setConfig({
      ...config,
      [name]: type === 'checkbox' ? checked : value
    });
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      // Settings are stored as strings; the response engine expects comma-separated IPs.
      const dataToSave = {
        ...config,
        wazuh_api_port: parseInt(config.wazuh_api_port, 10) || 55000,
        wazuh_indexer_port: parseInt(config.wazuh_indexer_port, 10) || 9200,
        alert_threshold_level: parseInt(config.alert_threshold_level, 10) || 10,
        polling_interval_seconds: parseInt(config.polling_interval_seconds, 10) || 60,
        auto_response_max_alert_age_seconds: parseInt(config.auto_response_max_alert_age_seconds, 10) || 600,
        whitelist_ips: config.whitelist_ips.split(',').map(ip => ip.trim()).filter(Boolean).join(',')
      };

      await api.updateSettings(dataToSave);
      toast.success('Settings saved successfully');
      fetchSettings(); // Refresh to ensure valid state
      setTimeout(fetchAutoStatus, 1500);
    } catch (error) {
      console.error('Error saving settings:', error);
      toast.error(error.response?.data?.message || 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const testWazuhConnection = async () => {
    setTestingWazuh(true);
    try {
      const res = await api.testWazuh();
      if (res.data.status === 'success') {
        toast.custom((t) => (
          <div className="bg-soc-card border border-soc-border p-4 rounded-lg shadow-lg flex items-center gap-3">
            <CheckCircle2 className="h-6 w-6 text-soc-success" />
            <div>
              <p className="text-white font-medium">Wazuh Connection Successful</p>
              <p className="text-sm text-slate-400">{res.data.message}</p>
            </div>
          </div>
        ));
      } else {
        toast.error('Wazuh Connection Failed');
      }
    } catch (error) {
      toast.error('Wazuh Connection Failed: ' + (error.response?.data?.message || error.message));
    } finally {
      setTestingWazuh(false);
    }
  };

  const testPfSenseConnection = async () => {
    setTestingPfSense(true);
    try {
      const res = await api.testPfSense();
      if (res.data.status === 'success') {
        toast.custom((t) => (
          <div className="bg-soc-card border border-soc-border p-4 rounded-lg shadow-lg flex items-center gap-3">
            <CheckCircle2 className="h-6 w-6 text-soc-success" />
            <div>
              <p className="text-white font-medium">pfSense Connection Successful</p>
              <p className="text-sm text-slate-400">{res.data.message}</p>
            </div>
          </div>
        ));
      } else {
        toast.error('pfSense Connection Failed');
      }
    } catch (error) {
      toast.error('pfSense Connection Failed: ' + (error.response?.data?.message || error.message));
    } finally {
      setTestingPfSense(false);
    }
  };

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center text-slate-300">
        <Loader2 className="h-8 w-8 animate-spin text-soc-accent" />
        <span className="ml-3 text-lg font-medium">Loading Settings...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Settings className="h-6 w-6 text-soc-accent" />
            System Configuration
          </h1>
          <p className="text-sm text-slate-400">Manage integrations, automated responses, and system behavior</p>
        </div>
        <button
          onClick={handleSave}
          disabled={saving}
          className="flex items-center gap-2 px-6 py-2 bg-soc-accent hover:bg-blue-600 disabled:opacity-70 text-white rounded-lg font-medium transition-colors"
        >
          {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
          Save Changes
        </button>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">

        {/* Wazuh Configuration Card */}
        <div className="bg-soc-card rounded-xl border border-soc-border p-6 space-y-6">
          <div className="flex items-center justify-between border-b border-soc-border pb-4">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Server className="h-5 w-5 text-blue-400" />
              Wazuh Integration
            </h2>
            <button
              onClick={testWazuhConnection}
              disabled={testingWazuh}
              className="px-3 py-1.5 bg-soc-border hover:bg-slate-600 text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
            >
              {testingWazuh && <Loader2 className="h-3 w-3 animate-spin" />}
              Test Connection
            </button>
          </div>
          <p className="text-sm text-slate-400">Save Changes before testing. The test uses saved settings and checks Manager authentication and Indexer connectivity.</p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="md:col-span-2">
              <label className="block text-sm font-medium text-slate-300 mb-1">Host/IP Address</label>
              <input type="text" name="wazuh_host" value={config.wazuh_host} onChange={handleChange} placeholder="127.0.0.1"
                className="w-full bg-soc-darker border border-soc-border rounded-lg px-3 py-2 text-white focus:border-soc-accent focus:ring-1" />
              <p className="text-xs text-slate-400 mt-1">Use 127.0.0.1 because Wazuh and STIS SOC run on UbuntuServer 10.10.10.20.</p>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">API Port</label>
              <input type="number" name="wazuh_api_port" value={config.wazuh_api_port} onChange={handleChange} placeholder="55000"
                className="w-full bg-soc-darker border border-soc-border rounded-lg px-3 py-2 text-white focus:border-soc-accent focus:ring-1" />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Indexer Port</label>
              <input type="number" name="wazuh_indexer_port" value={config.wazuh_indexer_port} onChange={handleChange} placeholder="9200"
                className="w-full bg-soc-darker border border-soc-border rounded-lg px-3 py-2 text-white focus:border-soc-accent focus:ring-1" />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">API Username</label>
              <input type="text" name="wazuh_api_user" value={config.wazuh_api_user} onChange={handleChange}
                className="w-full bg-soc-darker border border-soc-border rounded-lg px-3 py-2 text-white focus:border-soc-accent focus:ring-1" />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">API Password</label>
              <div className="relative">
                <input type={showWazuhApiPwd ? "text" : "password"} name="wazuh_api_password" value={config.wazuh_api_password} onChange={handleChange}
                  className="w-full bg-soc-darker border border-soc-border rounded-lg pl-3 pr-10 py-2 text-white focus:border-soc-accent focus:ring-1" />
                <button type="button" onClick={() => setShowWazuhApiPwd(!showWazuhApiPwd)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white">
                  {showWazuhApiPwd ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Indexer Username</label>
              <input type="text" name="wazuh_indexer_user" value={config.wazuh_indexer_user} onChange={handleChange}
                className="w-full bg-soc-darker border border-soc-border rounded-lg px-3 py-2 text-white focus:border-soc-accent focus:ring-1" />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Indexer Password</label>
              <div className="relative">
                <input type={showWazuhIdxPwd ? "text" : "password"} name="wazuh_indexer_password" value={config.wazuh_indexer_password} onChange={handleChange}
                  className="w-full bg-soc-darker border border-soc-border rounded-lg pl-3 pr-10 py-2 text-white focus:border-soc-accent focus:ring-1" />
                <button type="button" onClick={() => setShowWazuhIdxPwd(!showWazuhIdxPwd)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white">
                  {showWazuhIdxPwd ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>
          </div>
        </div>

        <div className="space-y-6">
          {/* pfSense Configuration Card */}
          <div className="bg-soc-card rounded-xl border border-soc-border p-6 space-y-6">
            <div className="flex items-center justify-between border-b border-soc-border pb-4">
              <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-red-400" />
                pfSense Integration
              </h2>
              <button
                onClick={testPfSenseConnection}
                disabled={testingPfSense}
                className="px-3 py-1.5 bg-soc-border hover:bg-slate-600 text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
              >
                {testingPfSense && <Loader2 className="h-3 w-3 animate-spin" />}
                Test Connection
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="md:col-span-2">
                <label className="block text-sm font-medium text-slate-300 mb-1">Host/IP Address</label>
                  <input type="text" name="pfsense_host" value={config.pfsense_host} onChange={handleChange} placeholder="https://10.10.10.1"
                  className="w-full bg-soc-darker border border-soc-border rounded-lg px-3 py-2 text-white focus:border-soc-accent focus:ring-1" />
              <p className="text-xs text-slate-400 mt-1">Topology value: https://10.10.10.1 (pfSense LAN).</p>
              </div>

              <div className="md:col-span-2">
                <label className="block text-sm font-medium text-slate-300 mb-1">API Key / Token</label>
                <div className="relative">
                  <input type={showPfSenseKey ? "text" : "password"} name="pfsense_api_key" value={config.pfsense_api_key} onChange={handleChange}
                    className="w-full bg-soc-darker border border-soc-border rounded-lg pl-3 pr-10 py-2 text-white focus:border-soc-accent focus:ring-1" />
                  <button type="button" onClick={() => setShowPfSenseKey(!showPfSenseKey)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white">
                    {showPfSenseKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Block Interface</label>
                <input type="text" name="pfsense_block_interface" value={config.pfsense_block_interface} onChange={handleChange} placeholder="wan"
                  className="w-full bg-soc-darker border border-soc-border rounded-lg px-3 py-2 text-white focus:border-soc-accent focus:ring-1" />
                <p className="text-xs text-slate-400 mt-1">The actual block rule must be on WAN and use the alias below as its source.</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Alias Name</label>
                  <input type="text" name="pfsense_alias_name" value={config.pfsense_alias_name} onChange={handleChange} placeholder="SOC_Blocklist"
                  className="w-full bg-soc-darker border border-soc-border rounded-lg px-3 py-2 text-white focus:border-soc-accent focus:ring-1" />
              </div>
            </div>
          </div>

          {/* Auto-Response Configuration Card */}
          <div className="bg-soc-card rounded-xl border border-soc-border p-6 space-y-6">
            <div className="flex items-center justify-between border-b border-soc-border pb-4">
              <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                <Zap className="h-5 w-5 text-amber-400" />
                Auto-Response Behavior
              </h2>

              <label className="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" name="auto_response_enabled" checked={config.auto_response_enabled} onChange={handleChange} className="sr-only peer" />
                <div className="w-11 h-6 bg-soc-darker peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-soc-accent rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-soc-success border border-soc-border"></div>
                <span className="ml-3 text-sm font-medium text-slate-300">
                  {config.auto_response_enabled ? 'Enabled' : 'Disabled'}
                </span>
              </label>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 opacity-100 transition-opacity" style={{ opacity: config.auto_response_enabled ? 1 : 0.6 }}>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Alert Threshold Level</label>
                <input type="number" min="1" max="15" name="alert_threshold_level" value={config.alert_threshold_level} onChange={handleChange}
                  disabled={!config.auto_response_enabled}
                  className="w-full bg-soc-darker border border-soc-border rounded-lg px-3 py-2 text-white focus:border-soc-accent focus:ring-1 disabled:opacity-50" />
                <p className="text-xs text-slate-400 mt-1">Block IPs with alerts &ge; this level.</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Polling Interval (seconds)</label>
                <input type="number" min="10" name="polling_interval_seconds" value={config.polling_interval_seconds} onChange={handleChange}
                  className="w-full bg-soc-darker border border-soc-border rounded-lg px-3 py-2 text-white focus:border-soc-accent focus:ring-1" />
                <p className="text-xs text-slate-400 mt-1">How often to fetch new alerts. Applied immediately after Save.</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Maximum Alert Age (seconds)</label>
                <input type="number" min="60" max="86400" name="auto_response_max_alert_age_seconds"
                  value={config.auto_response_max_alert_age_seconds} onChange={handleChange}
                  disabled={!config.auto_response_enabled}
                  className="w-full bg-soc-darker border border-soc-border rounded-lg px-3 py-2 text-white focus:border-soc-accent focus:ring-1 disabled:opacity-50" />
                <p className="text-xs text-slate-400 mt-1">Recent deferred alerts may be evaluated again within this window.</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Whitelist IPs (Comma-separated)</label>
                <textarea
                  name="whitelist_ips"
                  value={config.whitelist_ips}
                  onChange={handleChange}
                  placeholder="127.0.0.1, 192.168.1.1"
                  className="w-full bg-soc-darker border border-soc-border rounded-lg px-3 py-2 text-white focus:border-soc-accent focus:ring-1 h-24 resize-none"
                />
                <p className="text-xs text-slate-400 mt-1">IPs that will never be automatically blocked.</p>
              </div>
            </div>

            <div className="rounded-lg border border-soc-border bg-soc-darker/60 p-4 text-sm">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  {autoStatus?.scheduler_running && autoStatus?.last_status !== 'failure'
                    ? <CheckCircle2 className="h-5 w-5 text-soc-success" />
                    : <XCircle className="h-5 w-5 text-soc-danger" />}
                  <span className="font-medium text-white">Scheduler status</span>
                </div>
                <button type="button" onClick={fetchAutoStatus}
                  className="rounded bg-soc-border px-3 py-1 text-xs text-white hover:bg-slate-600">
                  Refresh
                </button>
              </div>
              <div className="mt-3 space-y-1 text-xs text-slate-400">
                <p>Running: <span className="text-slate-200">{autoStatus?.scheduler_running ? 'yes' : 'no'}</span></p>
                <p>Last cycle: <span className="text-slate-200">{autoStatus?.last_run ? new Date(autoStatus.last_run).toLocaleString() : 'never'}</span></p>
                <p>Result: <span className="text-slate-200">{autoStatus?.last_status || 'unknown'}</span></p>
                <p>Recent decisions: <span className="text-slate-200">{JSON.stringify(autoStatus?.recent_actions || {})}</span></p>
                {autoStatus?.last_error && <p className="text-soc-danger">{autoStatus.last_error}</p>}
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
};

export default SettingsPage;
