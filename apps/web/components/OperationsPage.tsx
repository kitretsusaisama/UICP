import { Activity, GitBranch, ListChecks, RadioTower } from 'lucide-react';
import { PageDefinition } from '../lib/page-registry';
import { ProviderHealthMatrix } from './operations/ProviderHealthMatrix';
import { ProviderFallbackGraph } from './operations/ProviderFallbackGraph';
import { QueueDepthChart } from './operations/QueueDepthChart';
import { SessionLineageGraph } from './operations/SessionLineageGraph';

export function OperationsPage({ page }: { page: PageDefinition }) {
  return (
    <div className="space-y-4">
      <section className="flex items-start justify-between">
        <div>
          <p className="text-sm text-muted">{page.module}</p>
          <h1 className="text-2xl font-semibold">{page.title}</h1>
          <p className="mt-1 max-w-3xl text-sm text-muted">{page.description}</p>
        </div>
        <div className="rounded border border-slate-300 bg-white px-3 py-2 text-xs">corr_live_01</div>
      </section>
      <section className="grid grid-cols-4 gap-3">
        {[
          ['Live status', Activity],
          ['Provider routing', RadioTower],
          ['Lineage', GitBranch],
          ['Audit state', ListChecks],
        ].map(([label, Icon]) => (
          <div key={String(label)} className="rounded border border-slate-200 bg-white p-3">
            <Icon className="mb-2 h-4 w-4 text-accent" />
            <div className="text-sm font-medium">{String(label)}</div>
            <div className="mt-2 text-2xl font-semibold">OK</div>
          </div>
        ))}
      </section>
      <section className="grid grid-cols-2 gap-3">
        <ProviderHealthMatrix />
        <QueueDepthChart />
        <ProviderFallbackGraph />
        <SessionLineageGraph />
      </section>
    </div>
  );
}
