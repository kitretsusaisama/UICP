import { Bell, Command, Search, ShieldCheck } from 'lucide-react';
import { pages } from '../lib/page-registry';

const nav = ['dashboard', 'auth', 'tenants', 'providers', 'communication', 'sessions', 'security', 'queues', 'audit', 'developer'];

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="flex h-14 items-center gap-3 px-4">
          <ShieldCheck className="h-5 w-5 text-accent" />
          <strong className="mr-3">UICP</strong>
          <select className="h-9 rounded border border-slate-300 px-2 text-sm">
            <option>Production</option>
            <option>Sandbox</option>
          </select>
          <select className="h-9 rounded border border-slate-300 px-2 text-sm">
            <option>Tenant A</option>
            <option>Tenant B</option>
          </select>
          <div className="ml-auto flex items-center gap-2">
            <button className="inline-flex h-9 w-9 items-center justify-center rounded border border-slate-300" aria-label="Search">
              <Search className="h-4 w-4" />
            </button>
            <button className="inline-flex h-9 w-9 items-center justify-center rounded border border-slate-300" aria-label="Command palette">
              <Command className="h-4 w-4" />
            </button>
            <button className="inline-flex h-9 w-9 items-center justify-center rounded border border-slate-300" aria-label="Alerts">
              <Bell className="h-4 w-4" />
            </button>
          </div>
        </div>
      </header>
      <div className="grid min-h-[calc(100vh-56px)] grid-cols-[240px_1fr]">
        <aside className="border-r border-slate-200 bg-white p-3">
          <nav className="space-y-1">
            {nav.map((item) => (
              <a key={item} className="block rounded px-3 py-2 text-sm hover:bg-slate-100" href={`/${item}/${item === 'dashboard' ? 'overview' : pages.find((page) => page.module === item)?.path.split('/')[2] ?? 'list'}`}>
                {item[0]?.toUpperCase()}{item.slice(1)}
              </a>
            ))}
          </nav>
        </aside>
        <main className="p-4">{children}</main>
      </div>
    </div>
  );
}
