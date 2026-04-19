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
