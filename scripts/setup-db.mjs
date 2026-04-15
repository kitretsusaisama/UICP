import mysql from 'mysql2/promise';
import { readdir, readFile } from 'fs/promises';
import { join } from 'path';
import { createHash } from 'crypto';

const conn = await mysql.createConnection({
  host: 'localhost', port: 3306,
  user: 'root', password: '123456789',
  multipleStatements: true,
  database: undefined,
});

// Create DB and user
await conn.query('CREATE DATABASE IF NOT EXISTS uicp_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
await conn.query("CREATE USER IF NOT EXISTS 'uicp_user'@'localhost' IDENTIFIED BY 'uicp_dev_password'");
await conn.query("GRANT ALL PRIVILEGES ON uicp_db.* TO 'uicp_user'@'localhost'");
await conn.query('FLUSH PRIVILEGES');
await conn.query('USE uicp_db');
console.log('Database and user ready');

// Run migrations
const migrationsDir = './migrations';
const files = (await readdir(migrationsDir))
  .filter(f => f.endsWith('.sql'))
  .sort();

// Ensure schema_versions table exists
await conn.query(`
  CREATE TABLE IF NOT EXISTS schema_versions (
    version VARCHAR(255) NOT NULL PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    checksum VARCHAR(64) NOT NULL,
    applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`);

const [applied] = await conn.query('SELECT version FROM schema_versions');
const appliedSet = new Set(applied.map(r => r.version));

for (const file of files) {
  const version = file.replace('.sql', '');
  if (appliedSet.has(version)) {
    console.log(`  skip ${file} (already applied)`);
    continue;
  }
  const sql = await readFile(join(migrationsDir, file), 'utf8');
  const checksum = createHash('sha256').update(sql).digest('hex');
  try {
    await conn.query(sql);
    await conn.query(
      'INSERT INTO schema_versions (version, filename, checksum) VALUES (?, ?, ?)',
      [version, file, checksum]
    );
    console.log(`  applied ${file}`);
  } catch (err) {
    console.error(`  FAILED ${file}: ${err.message}`);
    process.exit(1);
  }
}

await conn.end();
console.log('All migrations applied');
