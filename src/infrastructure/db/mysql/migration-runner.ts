import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

// mysql2 types — resolved at runtime; install with: npm install mysql2
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Pool = any;

export interface MigrationRecord {
  version: number;
  description: string;
  checksum: string;
  applied_at: Date;
  applied_by: string;
  duration_ms: number;
}

export interface MigrationFile {
  version: number;
  description: string;
  filename: string;
  sql: string;
  checksum: string;
}

const ADVISORY_LOCK_NAME = 'uicp_migration';
const ADVISORY_LOCK_TIMEOUT_S = 30;

/**
 * Reads all V*.sql migration files from the given directory,
 * sorted ascending by version number.
 */
function loadMigrationFiles(migrationsDir: string): MigrationFile[] {
  const files = fs
    .readdirSync(migrationsDir)
    .filter((f) => /^V\d+__.*\.sql$/i.test(f))
    .sort();

  return files.map((filename) => {
    const match = /^V(\d+)__(.+)\.sql$/i.exec(filename);
    if (!match) {
      throw new Error(`Unexpected migration filename format: ${filename}`);
    }
    const version = parseInt(match[1]!, 10);
    const description = match[2]!.replace(/_/g, ' ');
    const filePath = path.join(migrationsDir, filename);
    const sql = fs.readFileSync(filePath, 'utf8');
    const checksum = crypto.createHash('sha256').update(sql, 'utf8').digest('hex');

    return { version, description, filename, sql, checksum };
  });
}

/**
 * Ensures the schema_versions table exists before we try to query it.
 * This is a bootstrap step — the V001 migration creates it, but we need
 * it to exist before we can record V001 itself.
 */
async function ensureSchemaVersionsTable(pool: Pool): Promise<void> {
  await pool.execute(`
    CREATE TABLE IF NOT EXISTS schema_versions (
      version       INT UNSIGNED  NOT NULL,
      description   VARCHAR(255)  NOT NULL,
      checksum      CHAR(64)      NOT NULL,
      applied_at    DATETIME(3)   NOT NULL,
      applied_by    VARCHAR(128)  NOT NULL,
      duration_ms   INT UNSIGNED  NOT NULL,
      PRIMARY KEY (version)
    )
  `);
}

/**
 * Fetches all applied migration records from schema_versions.
 */
async function getAppliedMigrations(
  pool: Pool,
): Promise<Map<number, MigrationRecord>> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [rows]: [any[], any] = await pool.execute(
    'SELECT version, description, checksum, applied_at, applied_by, duration_ms FROM schema_versions ORDER BY version ASC',
  );

  const map = new Map<number, MigrationRecord>();
  for (const row of rows) {
    map.set(row.version, {
      version: row.version,
      description: row.description,
      checksum: row.checksum,
      applied_at: row.applied_at,
      applied_by: row.applied_by,
      duration_ms: row.duration_ms,
    });
  }
  return map;
}

/**
 * Runs a single migration SQL and records it in schema_versions.
 */
async function applyMigration(
  pool: Pool,
  migration: MigrationFile,
): Promise<void> {
  const conn = await pool.getConnection();
  try {
    const startMs = Date.now();

    // Split on semicolons to handle multi-statement migration files.
    // Filter out empty statements.
    const statements = migration.sql
      .split(';')
      .map((s) => s.trim())
      .filter((s) => s.length > 0 && !s.startsWith('--'));

    for (const stmt of statements) {
      await conn.execute(stmt);
    }

    const durationMs = Date.now() - startMs;

    await conn.execute(
      `INSERT INTO schema_versions (version, description, checksum, applied_at, applied_by, duration_ms)
       VALUES (?, ?, ?, NOW(3), ?, ?)`,
      [
        migration.version,
        migration.description,
        migration.checksum,
        os.hostname(),
        durationMs,
      ],
    );
  } finally {
    conn.release();
  }
}

/**
 * Acquires a MySQL advisory lock to prevent concurrent migrations.
 * Returns true if the lock was acquired, false if timed out.
 */
async function acquireAdvisoryLock(pool: Pool): Promise<boolean> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [rows]: [any[], any] = await pool.execute(
    'SELECT GET_LOCK(?, ?) AS lock_result',
    [ADVISORY_LOCK_NAME, ADVISORY_LOCK_TIMEOUT_S],
  );
  const result: number | null = rows[0]?.lock_result;
  return result === 1;
}

/**
 * Releases the MySQL advisory lock.
 */
async function releaseAdvisoryLock(pool: Pool): Promise<void> {
  await pool.execute('SELECT RELEASE_LOCK(?)', [ADVISORY_LOCK_NAME]);
}

/**
 * Main migration runner.
 *
 * - Acquires an advisory lock to prevent concurrent runs.
 * - Bootstraps the schema_versions table if it doesn't exist.
 * - For each migration file (sorted by version):
 *   - If already applied: verifies the stored SHA-256 checksum matches.
 *   - If not applied: runs the SQL and records it in schema_versions.
 * - Releases the advisory lock when done.
 *
 * @param pool       mysql2 Pool instance
 * @param migrationsDir  Absolute path to the migrations directory
 */
export async function runMigrations(
  pool: Pool,
  migrationsDir: string,
): Promise<void> {
  const locked = await acquireAdvisoryLock(pool);
  if (!locked) {
    throw new Error(
      `Could not acquire advisory lock '${ADVISORY_LOCK_NAME}' within ${ADVISORY_LOCK_TIMEOUT_S}s. ` +
        'Another migration process may be running.',
    );
  }

  try {
    await ensureSchemaVersionsTable(pool);

    const migrationFiles = loadMigrationFiles(migrationsDir);
    const applied = await getAppliedMigrations(pool);

    for (const migration of migrationFiles) {
      const record = applied.get(migration.version);

      if (record) {
        // Already applied — verify checksum integrity
        if (record.checksum !== migration.checksum) {
          throw new Error(
            `Checksum mismatch for migration V${String(migration.version).padStart(3, '0')} ` +
              `(${migration.filename}).\n` +
              `  Stored:   ${record.checksum}\n` +
              `  Computed: ${migration.checksum}\n` +
              'Migration file has been modified after it was applied. This is not allowed.',
          );
        }
        // Checksum matches — skip
        continue;
      }

      // Not yet applied — run it
      console.log(
        `[MigrationRunner] Applying V${String(migration.version).padStart(3, '0')}: ${migration.description}`,
      );
      await applyMigration(pool, migration);
      console.log(
        `[MigrationRunner] Applied  V${String(migration.version).padStart(3, '0')}: ${migration.description}`,
      );
    }

    console.log('[MigrationRunner] All migrations up to date.');
  } finally {
    await releaseAdvisoryLock(pool);
  }
}
