const fs = require('fs');
const path = require('path');
const file = path.join(__dirname, '../src/infrastructure/queue/bullmq-queue.adapter.ts');

let code = fs.readFileSync(file, 'utf8');

code = code.replace(
  /const count = await q\.getJobCountByTypes\('wait', 'paused', 'delayed'\);\n\s*if \(count >= maxQueueLen\) \{[\s\S]*?\}/,
  `const sampleRate = this.config.get<number>('BULLMQ_QUEUE_LEN_SAMPLE_RATE') ?? 100;
    if (sampleRate > 0 && Math.floor(Math.random() * sampleRate) === 0) {
      const count = await q.getJobCountByTypes('wait', 'paused', 'delayed');
      if (count >= maxQueueLen) {
        this.logger.error({ queue, maxQueueLen, count }, 'QUEUE COLLAPSE DEFENSE: Queue is full, dropping job');
        const error: any = new Error(\`QUEUE_FULL: The queue \${queue} has reached its maximum capacity of \${maxQueueLen}\`);
        error.code = 'QUEUE_FULL';
        throw error;
      }
    }`
);

fs.writeFileSync(file, code);
