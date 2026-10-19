// Ambil enam alert terbaru berkala; penanda dibaca disimpan per akun pada browser.
import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Bell,
  CheckCheck,
  ChevronDown,
  ChevronRight,
  Loader2,
  LogOut,
  Menu,
  ScrollText,
  Settings,
  ShieldAlert
} from 'lucide-react';
import api from '../../services/api';
import { useAuth } from '../../context/AuthContext';

const formatRelativeTime = (value) => {
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) return '-';

  const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
  if (seconds < 60) return 'Just now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(value).toLocaleDateString();
};

const getLevelClasses = (level) => {
  if (level >= 12) return 'bg-red-500/15 text-red-400 border-red-500/30';
  if (level >= 10) return 'bg-orange-500/15 text-orange-400 border-orange-500/30';
  return 'bg-blue-500/15 text-blue-400 border-blue-500/30';
};

const Header = ({ title, toggleSidebar }) => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const menuRef = useRef(null);
  const [activeMenu, setActiveMenu] = useState(null);
  const [notifications, setNotifications] = useState([]);
  const [notificationsLoading, setNotificationsLoading] = useState(true);
  const [notificationsError, setNotificationsError] = useState(false);
  const [readAlertIds, setReadAlertIds] = useState([]);

  const storageKey = `mini-soc-read-alerts-${user?.id || user?.username || 'user'}`;

  useEffect(() => {
    try {
      const storedIds = JSON.parse(localStorage.getItem(storageKey) || '[]');
      setReadAlertIds(Array.isArray(storedIds) ? storedIds.map(String) : []);
    } catch {
      setReadAlertIds([]);
    }
  }, [storageKey]);

  useEffect(() => {
    let active = true;

    const fetchNotifications = async () => {
      try {
        const response = await api.getAlerts({ page: 1, per_page: 6, min_level: 7 });
        if (!active) return;
        setNotifications(response.data.items || []);
        setNotificationsError(false);
      } catch (error) {
        if (!active) return;
        console.error('Error fetching header notifications:', error);
        setNotificationsError(true);
      } finally {
        if (active) setNotificationsLoading(false);
      }
    };

    fetchNotifications();
    const intervalId = window.setInterval(fetchNotifications, 30000);
    return () => {
      active = false;
      window.clearInterval(intervalId);
    };
  }, []);

  useEffect(() => {
    const handleOutsideClick = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) setActiveMenu(null);
    };
    const handleEscape = (event) => {
      if (event.key === 'Escape') setActiveMenu(null);
    };

    document.addEventListener('mousedown', handleOutsideClick);
    document.addEventListener('keydown', handleEscape);
    return () => {
      document.removeEventListener('mousedown', handleOutsideClick);
      document.removeEventListener('keydown', handleEscape);
    };
  }, []);

  const saveReadAlertIds = (ids) => {
    const uniqueIds = [...new Set(ids.map(String))].slice(-200);
    setReadAlertIds(uniqueIds);
    localStorage.setItem(storageKey, JSON.stringify(uniqueIds));
  };

  const markAlertRead = (alertId) => {
    saveReadAlertIds([...readAlertIds, alertId]);
  };

  const markAllRead = () => {
    saveReadAlertIds([...readAlertIds, ...notifications.map((alert) => alert.id)]);
  };

  const openAlert = (alert) => {
    markAlertRead(alert.id);
    setActiveMenu(null);
    navigate(`/alerts?alert=${alert.id}`);
  };

  const navigateFromMenu = (path) => {
    setActiveMenu(null);
    navigate(path);
  };

  const unreadCount = notifications.filter((alert) => !readAlertIds.includes(String(alert.id))).length;
  const displayName = user?.full_name || user?.username || 'User';
  const roleName = user?.role
    ? user.role.charAt(0).toUpperCase() + user.role.slice(1)
    : 'User';

  return (
    <header className="relative z-30 h-16 bg-soc-card border-b border-soc-border flex items-center justify-between px-4 sm:px-6">
      <div className="flex items-center min-w-0">
        <button
          type="button"
          aria-label="Open navigation menu"
          className="mr-4 text-gray-400 hover:text-white focus:outline-none md:hidden"
          onClick={toggleSidebar}
        >
          <Menu className="w-6 h-6" />
        </button>
        <h1 className="text-xl font-semibold text-white truncate">{title}</h1>
      </div>

      <div ref={menuRef} className="relative flex items-center gap-2 sm:gap-3">
        <div className="relative">
          <button
            type="button"
            aria-label={`Notifications${unreadCount ? `, ${unreadCount} unread` : ''}`}
            aria-haspopup="menu"
            aria-expanded={activeMenu === 'notifications'}
            onClick={() => setActiveMenu(activeMenu === 'notifications' ? null : 'notifications')}
            className="relative p-2 rounded-lg text-gray-400 hover:text-white hover:bg-soc-border/60 transition-colors"
          >
            <Bell className="w-5 h-5" />
            {unreadCount > 0 && (
              <span className="absolute -top-1 -right-1 min-w-4 h-4 px-1 flex items-center justify-center bg-soc-danger text-white text-[10px] font-bold rounded-full ring-2 ring-soc-card">
                {unreadCount > 9 ? '9+' : unreadCount}
              </span>
            )}
          </button>

          {activeMenu === 'notifications' && (
            <div className="fixed left-4 right-4 top-16 mt-2 sm:absolute sm:left-auto sm:right-0 sm:top-auto sm:w-96 bg-soc-card border border-soc-border rounded-xl shadow-2xl overflow-hidden">
              <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-soc-border bg-soc-darker/50">
                <div>
                  <h2 className="text-sm font-semibold text-white">Security Notifications</h2>
                  <p className="text-xs text-slate-400">Latest alerts at level 7 or higher</p>
                </div>
                {unreadCount > 0 && (
                  <button
                    type="button"
                    onClick={markAllRead}
                    className="inline-flex items-center gap-1 text-xs text-soc-accent hover:text-blue-300 whitespace-nowrap"
                  >
                    <CheckCheck className="w-4 h-4" /> Mark all read
                  </button>
                )}
              </div>

              <div className="max-h-96 overflow-y-auto">
                {notificationsLoading ? (
                  <div className="flex items-center justify-center py-10 text-slate-400">
                    <Loader2 className="w-5 h-5 animate-spin text-soc-accent" />
                  </div>
                ) : notificationsError ? (
                  <div className="px-5 py-8 text-center">
                    <ShieldAlert className="w-8 h-8 mx-auto mb-2 text-soc-danger" />
                    <p className="text-sm text-slate-300">Unable to load notifications</p>
                    <p className="text-xs text-slate-500 mt-1">Check the backend connection.</p>
                  </div>
                ) : notifications.length === 0 ? (
                  <div className="px-5 py-8 text-center">
                    <CheckCheck className="w-8 h-8 mx-auto mb-2 text-soc-success" />
                    <p className="text-sm text-slate-300">No recent security alerts</p>
                  </div>
                ) : (
                  notifications.map((alert) => {
                    const unread = !readAlertIds.includes(String(alert.id));
                    return (
                      <button
                        type="button"
                        key={alert.id}
                        onClick={() => openAlert(alert)}
                        className="w-full flex gap-3 px-4 py-3 text-left border-b border-soc-border/70 last:border-b-0 hover:bg-soc-dark/70 transition-colors"
                      >
                        <span className={`mt-0.5 shrink-0 px-2 py-0.5 rounded border text-[11px] font-semibold ${getLevelClasses(alert.rule_level)}`}>
                          L{alert.rule_level}
                        </span>
                        <span className="min-w-0 flex-1">
                          <span className="flex items-start gap-2">
                            <span className={`block flex-1 text-sm leading-5 line-clamp-2 ${unread ? 'font-semibold text-white' : 'text-slate-300'}`}>
                              {alert.rule_description || `Wazuh rule ${alert.rule_id}`}
                            </span>
                            {unread && <span className="mt-1.5 w-2 h-2 shrink-0 bg-soc-accent rounded-full" />}
                          </span>
                          <span className="mt-1 flex items-center gap-2 text-xs text-slate-500">
                            <span>{alert.src_ip || alert.agent_name || 'System'}</span>
                            <span aria-hidden="true">•</span>
                            <span>{formatRelativeTime(alert.timestamp || alert.fetched_at)}</span>
                          </span>
                        </span>
                      </button>
                    );
                  })
                )}
              </div>

              <button
                type="button"
                onClick={() => navigateFromMenu('/alerts')}
                className="w-full flex items-center justify-center gap-1 px-4 py-3 border-t border-soc-border bg-soc-darker/40 text-sm font-medium text-soc-accent hover:bg-soc-dark transition-colors"
              >
                View all alerts <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>

        <div className="relative">
          <button
            type="button"
            aria-label="Open profile menu"
            aria-haspopup="menu"
            aria-expanded={activeMenu === 'profile'}
            onClick={() => setActiveMenu(activeMenu === 'profile' ? null : 'profile')}
            className="flex items-center gap-2 p-1 rounded-lg hover:bg-soc-border/60 transition-colors"
          >
            <span className="w-8 h-8 rounded-full bg-soc-accent/15 border border-soc-accent/30 flex items-center justify-center text-sm font-semibold text-soc-accent uppercase">
              {displayName.charAt(0)}
            </span>
            <span className="hidden md:block max-w-32 text-sm font-medium text-slate-200 truncate">{displayName}</span>
            <ChevronDown className={`hidden sm:block w-4 h-4 text-slate-400 transition-transform ${activeMenu === 'profile' ? 'rotate-180' : ''}`} />
          </button>

          {activeMenu === 'profile' && (
            <div className="absolute right-0 mt-2 w-72 bg-soc-card border border-soc-border rounded-xl shadow-2xl overflow-hidden">
              <div className="flex items-center gap-3 p-4 border-b border-soc-border bg-soc-darker/50">
                <div className="w-11 h-11 shrink-0 rounded-full bg-soc-accent/15 border border-soc-accent/30 flex items-center justify-center text-lg font-semibold text-soc-accent uppercase">
                  {displayName.charAt(0)}
                </div>
                <div className="min-w-0">
                  <p className="font-semibold text-white truncate">{displayName}</p>
                  <p className="text-xs text-slate-400 truncate">@{user?.username || 'user'} · {roleName}</p>
                </div>
              </div>

              <div className="px-4 py-3 border-b border-soc-border text-xs text-slate-400">
                <span className="block mb-1">Last login</span>
                <span className="text-slate-200">
                  {user?.last_login ? new Date(user.last_login).toLocaleString() : 'Not available'}
                </span>
              </div>

              <div className="p-2">
                <button
                  type="button"
                  onClick={() => navigateFromMenu('/settings')}
                  className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-slate-300 hover:text-white hover:bg-soc-border/60 transition-colors"
                >
                  <Settings className="w-4 h-4" /> Settings
                </button>
                <button
                  type="button"
                  onClick={() => navigateFromMenu('/audit')}
                  className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-slate-300 hover:text-white hover:bg-soc-border/60 transition-colors"
                >
                  <ScrollText className="w-4 h-4" /> Audit Log
                </button>
                <div className="my-2 border-t border-soc-border" />
                <button
                  type="button"
                  onClick={() => {
                    setActiveMenu(null);
                    logout();
                  }}
                  className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-soc-danger hover:bg-soc-danger/10 transition-colors"
                >
                  <LogOut className="w-4 h-4" /> Sign out
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};

export default Header;
