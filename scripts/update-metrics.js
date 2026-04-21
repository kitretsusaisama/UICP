const fs = require('fs');
const path = require('path');
const file = path.join(__dirname, '../src/application/services/platform-ops/metrics.service.ts');

let code = fs.readFileSync(file, 'utf8');

const reg = /this\.socAlertsCriticalTotal = new client\.Counter\(\{[\s\S]*?\}\);/;
code = code.replace(reg, `$&
    this.extensionCommandTotal = new client.Counter({
      name: 'extension_command_total',
      help: 'Total extension commands executed',
      registers: [this.registry],
    });
    this.extensionCommandFailed = new client.Counter({
      name: 'extension_command_failed',
      help: 'Total extension commands failed',
      registers: [this.registry],
    });
    this.extensionCommandLatency = new client.Histogram({
      name: 'extension_command_latency_ms',
      help: 'Latency of extension commands',
      buckets: [10, 50, 100, 250, 500, 1000, 2000],
      registers: [this.registry],
    });`);

fs.writeFileSync(file, code);
const fs2 = require('fs');
const path2 = require('path');
const file2 = path2.join(__dirname, '../src/application/services/platform-ops/metrics.service.ts');

let code2 = fs2.readFileSync(file2, 'utf8');

const reg2 = /this\.extensionCommandLatency = new client\.Histogram\(\{[\s\S]*?\}\);/;
code2 = code2.replace(reg2, `$&
    this.deprecatedApiTotal = new client.Counter({
      name: 'core_api_requests_total',
      help: 'Total deprecated /core API requests',
      labelNames: ['route', 'client_id'],
      registers: [this.registry],
    });`);

const typeReg = /public readonly extensionCommandLatency: client\.Histogram;/;
code2 = code2.replace(typeReg, `$&
  public readonly deprecatedApiTotal: client.Counter;`);

fs2.writeFileSync(file2, code2);
