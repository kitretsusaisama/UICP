import * as mysql from 'mysql2/promise';
import { runMigrations } from '../src/infrastructure/db/mysql/migration-runner';

async function main() {
  const db = await mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '3306'),
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '123456789',
    database: process.env.DB_NAME || 'uicp',
    waitForConnections: true,
    connectionLimit: 5,
  });

  const migrationsDir = process.argv[2] || './migrations';

  console.log(`Running migrations from: ${migrationsDir}`);
  await runMigrations(db, migrationsDir);
  console.log('Done.');
  await db.end();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});