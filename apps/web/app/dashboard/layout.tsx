'use client';

import { ReactNode, useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useAuthStore } from '@/stores/auth.store';
import {
  LayoutDashboard, Users, Shield, Activity, Database, FileText,
  BarChart3, Building2, Settings, Code2, ChevronLeft, ChevronRight,
  Bell, LogOut, Menu, X, Layers, Key
} from 'lucide-react';

const NAV_ITEMS = [
  { label: 'Overview', href: '/dashboard/overview', icon: LayoutDashboard },
  { label: 'Users', href: '/dashboard/users', icon: Users },
  { label: 'Sessions', href: '/dashboard/sessions', icon: Activity },
  { label: 'API Keys', href: '/dashboard/api-keys', icon: Key },
  { label: 'Providers', href: '/dashboard/providers', icon: Database },
  { label: 'Security', href: '/dashboard/security', icon: Shield },
  { label: 'Queues', href: '/dashboard/queues', icon: Layers },
  { label: 'Audit', href: '/dashboard/audit', icon: FileText },
  { label: 'Analytics', href: '/dashboard/analytics', icon: BarChart3 },
  { label: 'Tenants', href: '/dashboard/tenants', icon: Building2 },
  { label: 'Developer', href: '/dashboard/developer', icon: Code2 },
  { label: 'Settings', href: '/dashboard/settings', icon: Settings },
];

export default function DashboardLayout({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { accessToken, logout } = useAuthStore();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    if (!accessToken) {
      router.replace('/auth/login');
    }
  }, [accessToken, router]);

  if (!accessToken) {
    return null;
  }

  const handleLogout = () => {
    logout();
    router.push('/auth/login');
  };

  return (
    <div className="flex h-screen overflow-hidden bg-surface">
      {/* Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 bg-white border-r border-gray-200 transition-all duration-200 ${
          collapsed ? 'w-16' : 'w-64'
        } ${mobileOpen ? 'translate-x-0' : '-translate-x-full'} md:relative md:translate-x-0`}
      >
        {/* Logo */}
        <div className="flex items-center h-16 px-4 border-b border-gray-200">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 bg-accent rounded-lg flex items-center justify-center">
              <span className="text-white font-bold text-sm">U</span>
            </div>
            {!collapsed && <span className="font-semibold text-ink">UICP</span>}
          </div>
          <button
            onClick={() => setMobileOpen(false)}
            className="ml-auto md:hidden text-muted hover:text-ink"
          >
            <X size={20} />
          </button>
        </div>

        {/* Nav */}
        <nav className="p-2 space-y-1 overflow-y-auto" style={{ height: 'calc(100vh - 64px)' }}>
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => setMobileOpen(false)}
                className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                  active
                    ? 'bg-accent/10 text-accent font-medium'
                    : 'text-muted hover:text-ink hover:bg-gray-50'
                }`}
                title={collapsed ? item.label : undefined}
              >
                <Icon size={18} />
                {!collapsed && <span>{item.label}</span>}
              </Link>
            );
          })}
        </nav>

        {/* Collapse toggle */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="hidden md:flex absolute -right-3 top-20 w-6 h-6 bg-white border border-gray-200 rounded-full items-center justify-center text-muted hover:text-ink shadow-sm"
        >
          {collapsed ? <ChevronRight size={12} /> : <ChevronLeft size={12} />}
        </button>
      </aside>

      {/* Overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 md:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Main */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top bar */}
        <header className="h-16 bg-white border-b border-gray-200 flex items-center px-4 gap-4">
          <button
            onClick={() => setMobileOpen(true)}
            className="md:hidden text-muted hover:text-ink"
          >
            <Menu size={20} />
          </button>

          <div className="flex-1" />

          {/* Notifications */}
          <button className="relative p-2 text-muted hover:text-ink rounded-lg hover:bg-gray-50">
            <Bell size={18} />
            <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full" />
          </button>

          {/* User menu */}
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 bg-accent/10 rounded-full flex items-center justify-center">
              <span className="text-accent font-medium text-sm">V</span>
            </div>
            <button
              onClick={handleLogout}
              className="p-2 text-muted hover:text-danger rounded-lg hover:bg-gray-50"
              title="Sign out"
            >
              <LogOut size={16} />
            </button>
          </div>
        </header>

        {/* Content */}
        <main className="flex-1 overflow-y-auto p-6">
          {children}
        </main>
      </div>
    </div>
  );
}
