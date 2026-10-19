// Tampilkan inventaris Agent dari Wazuh; konfigurasi pemasangan tetap dilakukan pada target.
import React, { useCallback, useEffect, useState } from 'react';
import { RefreshCw, Server } from 'lucide-react';
import api from '../services/api';

const asArray = (value) => Array.isArray(value) ? value : [];

const show = (value) => {
  if (value == null || value === '') return '-';
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
};

const label = (item) => {
  if (!item || typeof item !== 'object') return show(item);
  for (const key of ['name', 'location', 'path', 'directories', 'localfile']) {
    if (item[key] != null) return show(item[key]);
  }
  return show(item);
};

const sections = {
  log_sources: 'Sumber log aktif',
  file_integrity: 'Konfigurasi FIM',
  services: 'Service terpasang',
  ports: 'Port terdeteksi',
  packages: 'Paket terpasang',
};

// A bad Manager response must show an error instead of blanking the dashboard.
class InventoryErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  render() {
    if (!this.state.error) return this.props.children;

    return (
      <div className="rounded-xl border border-red-700 bg-soc-card p-6 text-white">
        <h1 className="text-xl font-semibold">Inventaris gagal ditampilkan</h1>
        <p className="mt-2 text-slate-300">Periksa Console browser dan backend.log, lalu muat ulang halaman.</p>
        <p className="mt-2 break-all text-sm text-red-300">{show(this.state.error.message)}</p>
        <button
          onClick={() => this.setState({ error: null })}
          className="mt-4 rounded-lg bg-soc-accent px-4 py-2"
        >
          Coba lagi
        </button>
      </div>
    );
  }
}

function AssetsContent() {
  const [agents, setAgents] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [inventory, setInventory] = useState(null);
  const [loadingAgents, setLoadingAgents] = useState(true);
  const [loadingInventory, setLoadingInventory] = useState(false);
  const [agentsError, setAgentsError] = useState('');
  const [inventoryError, setInventoryError] = useState('');

  const refresh = useCallback(async () => {
    setLoadingAgents(true);
    setAgentsError('');
    try {
      const response = await api.getAssetAgents();
      setAgents(asArray(response.data?.items));
    } catch (error) {
      setAgentsError(error.response?.data?.message || error.message);
    } finally {
      setLoadingAgents(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const inspect = async (id) => {
    setSelectedId(String(id));
    setInventory(null);
    setInventoryError('');
    setLoadingInventory(true);
    try {
      const response = await api.getAgentInventory(id);
      setInventory(response.data);
    } catch (error) {
      setInventoryError(error.response?.data?.message || error.message);
    } finally {
      setLoadingInventory(false);
    }
  };

  const selected = agents.find((agent) => String(agent.id) === selectedId);

  return (
    <div className="space-y-6 pb-10">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold text-white">
            <Server className="text-soc-accent" /> Inventaris Wazuh
          </h1>
          <p className="text-sm text-slate-400">
            Server yang terdaftar sebagai Wazuh Agent dan konfigurasi monitoring yang dilaporkan Manager.
          </p>
        </div>
        <button
          onClick={refresh}
          disabled={loadingAgents}
          className="rounded-lg bg-soc-border px-4 py-2 text-white disabled:opacity-50"
        >
          <RefreshCw size={16} className="mr-2 inline" />Refresh
        </button>
      </div>

      <p className="rounded-lg border border-soc-border bg-soc-card p-4 text-sm text-slate-300">
        Halaman ini hanya membaca inventaris Wazuh. Agent, website, domain, dan service dikonfigurasi
        pada server target. Nama domain tidak otomatis menjadi daftar website tersendiri.
      </p>

      {agentsError && (
        <p role="alert" className="rounded-lg border border-amber-700 bg-soc-card p-4 text-amber-300">
          Gagal membaca Agent: {agentsError}. Daftar lama tetap ditampilkan.
        </p>
      )}

      <section className="space-y-3">
        <h2 className="text-lg font-semibold text-white">Server Wazuh ({agents.length})</h2>
        {loadingAgents && <p className="text-slate-400">Memuat Agent...</p>}
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {agents.map((agent) => (
            <button
              key={show(agent.id)}
              onClick={() => inspect(agent.id)}
              className={`rounded-xl border bg-soc-card p-4 text-left ${
                selectedId === String(agent.id) ? 'border-soc-accent' : 'border-soc-border'
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold text-white">{show(agent.name)}</span>
                <span className={`text-xs ${agent.status === 'active' ? 'text-green-400' : 'text-amber-400'}`}>
                  {show(agent.status)}
                </span>
              </div>
              <p className="mt-1 text-sm text-slate-400">
                Agent {show(agent.id)} · {show(agent.ip)} · {show(agent.os?.name)}
              </p>
            </button>
          ))}
        </div>
        {!loadingAgents && !agents.length && !agentsError && (
          <p className="rounded-xl border border-soc-border bg-soc-card p-5 text-slate-400">
            Belum ada Agent. Pasang dan daftarkan Wazuh Agent pada server target, lalu klik Refresh.
          </p>
        )}
      </section>

      {selectedId && (
        <section className="space-y-5 rounded-xl border border-soc-border bg-soc-card p-5">
          <div>
            <h2 className="text-xl font-semibold text-white">
              {show(selected?.name || inventory?.agent?.name || selectedId)}
            </h2>
            <p className="text-sm text-slate-400">
              Agent {selectedId} · {show(selected?.ip || inventory?.agent?.ip)} ·{' '}
              {show(selected?.os?.name || inventory?.agent?.os?.name)}
            </p>
          </div>
          {loadingInventory && <p className="text-slate-400">Membaca inventaris...</p>}
          {inventoryError && (
            <p role="alert" className="rounded border border-amber-700 p-3 text-amber-300">
              {inventoryError}
            </p>
          )}
          {inventory && (
            <div className="space-y-3">
              {Object.entries(sections).map(([key, title]) => {
                const section = inventory.sections?.[key] || {};
                const items = asArray(section.items);
                return (
                  <details
                    key={key}
                    open={key === 'log_sources' || key === 'file_integrity'}
                    className="rounded-lg border border-soc-border bg-soc-darker p-3 text-sm"
                  >
                    <summary className="cursor-pointer font-medium text-white">
                      {title} ({show(section.total ?? items.length)})
                    </summary>
                    {inventory.errors?.[key] && (
                      <p className="mt-2 text-amber-300">Gagal membaca bagian ini: {show(inventory.errors[key])}</p>
                    )}
                    {Number(section.total) > items.length && (
                      <p className="mt-2 text-amber-300">Hanya {items.length} entri pertama yang dikembalikan Wazuh.</p>
                    )}
                    {items.length ? (
                      <div className="mt-2 max-h-80 space-y-1 overflow-auto">
                        {items.map((item, index) => (
                          <details key={index} className="rounded bg-soc-card px-2 py-1 text-slate-300">
                            <summary className="cursor-pointer break-all">{label(item)}</summary>
                            <pre className="overflow-x-auto whitespace-pre-wrap break-all text-xs">
                              {JSON.stringify(item, null, 2)}
                            </pre>
                          </details>
                        ))}
                      </div>
                    ) : !inventory.errors?.[key] && (
                      <p className="mt-2 text-slate-400">Belum ada data yang dilaporkan.</p>
                    )}
                  </details>
                );
              })}
            </div>
          )}
        </section>
      )}
    </div>
  );
}

export default function AssetsPage() {
  return (
    <InventoryErrorBoundary>
      <AssetsContent />
    </InventoryErrorBoundary>
  );
}
