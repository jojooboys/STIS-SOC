// Definisikan navigasi dashboard dan tandai halaman yang sedang aktif.
import React from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, Bell, ShieldBan, ScrollText, Settings, Shield, LogOut, X, Globe2 } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

const Sidebar = ({ isOpen, toggleSidebar }) => {
  const { user, logout } = useAuth();

  const navItems = [
    { name: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
    { name: 'Alerts', path: '/alerts', icon: Bell },
    { name: 'Blocked IPs', path: '/blocked-ips', icon: ShieldBan },
    { name: 'Audit Log', path: '/audit', icon: ScrollText },
    { name: 'Inventaris Wazuh', path: '/assets', icon: Globe2 },
    { name: 'Settings', path: '/settings', icon: Settings },
  ];

  const sidebarClasses = `
    fixed inset-y-0 left-0 z-50 w-64 bg-soc-card border-r border-soc-border
    transform transition-transform duration-300 ease-in-out flex flex-col
    ${isOpen ? 'translate-x-0' : '-translate-x-full'}
    md:translate-x-0 md:static md:h-screen
  `;

  return (
    <>
      {/* Mobile overlay */}
      {isOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 md:hidden"
          onClick={toggleSidebar}
        />
      )}

      <aside className={sidebarClasses}>
        <div className="flex items-center justify-between h-16 px-6 border-b border-soc-border">
          <div className="flex items-center space-x-3 text-soc-accent">
            <Shield className="w-8 h-8" />
            <span className="text-xl font-bold text-white tracking-tight">STIS SOC</span>
          </div>
          <button className="md:hidden text-gray-400 hover:text-white" onClick={toggleSidebar}>
            <X className="w-6 h-6" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto py-6 px-4">
          <nav className="space-y-2">
            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  className={({ isActive }) => `
                    flex items-center px-4 py-3 text-sm font-medium rounded-lg transition-colors
                    ${isActive
                      ? 'bg-soc-accent/10 text-soc-accent'
                      : 'text-gray-400 hover:bg-soc-border/50 hover:text-gray-200'
                    }
                  `}
                >
                  <Icon className="w-5 h-5 mr-3" />
                  {item.name}
                </NavLink>
              );
            })}
          </nav>
        </div>

        <div className="p-4 border-t border-soc-border">
          <div className="flex items-center mb-4 px-2">
            <div className="w-8 h-8 rounded-full bg-soc-border flex items-center justify-center text-gray-300 font-bold uppercase">
              {user?.username?.charAt(0) || 'U'}
            </div>
            <div className="ml-3 truncate">
              <p className="text-sm font-medium text-white">{user?.username || 'User'}</p>
              <p className="text-xs text-gray-400 truncate">Administrator</p>
            </div>
          </div>
          <button
            onClick={logout}
            className="flex items-center w-full px-4 py-2 text-sm font-medium text-gray-400 rounded-lg hover:bg-soc-danger/10 hover:text-soc-danger transition-colors"
          >
            <LogOut className="w-5 h-5 mr-3" />
            Sign out
          </button>
        </div>
      </aside>
    </>
  );
};

export default Sidebar;
