import {
  DynamicModule,
  Module,
  OnApplicationShutdown,
  Provider,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CircuitBreaker, CIRCUIT_BREAKER_CONFIGS } from '../../resilience/circuit-breaker';
/** Injection token for the mysql2 connection pool */
export const MYSQL_POOL = Symbol('MYSQL_POOL');

/** Injection token for the transaction factory */
export const DB_TRANSACTION = Symbol('DB_TRANSACTION');

/**
 * Minimal typed interface for a mysql2 Pool / Connection so that
 * `pool.execute<RowType[]>(sql, params)` is accepted by TypeScript strict mode.
 * The actual runtime object is a mysql2 Pool; we only type the surface we use.
 */
export interface DbConnection {
  execute<T = unknown>(sql: string, params?: unknown[]): Promise<[T, unknown]>;
  beginTransaction(): Promise<void>;
  commit(): Promise<void>;
  rollback(): Promise<void>;
  release(): void;
}

export interface DbPool {
  execute<T = unknown>(sql: string, params?: unknown[]): Promise<[T, unknown]>;
  getConnection(): Promise<DbConnection>;
  end(): Promise<void>;
}

/** Type alias for a mysql2 Connection (used for transaction passing to repositories) */
export type DbTransaction = DbConnection;

/** Factory type for running code inside a transaction */
export type TransactionFactory = <T>(
  fn: (conn: DbTransaction) => Promise<T>,
) => Promise<T>;

@Module({})
export class MysqlModule implements OnApplicationShutdown {
  private static pool: DbPool | null = null;

  static forRoot(): DynamicModule {
    const poolProvider: Provider = {
      provide: MYSQL_POOL,
      useFactory: (config: ConfigService): DbPool => {
        // Lazy require so the module compiles even if mysql2 is not yet installed.
        // Install with: npm install mysql2
        // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
        const mysql = require('mysql2/promise') as { createPool: (opts: Record<string, unknown>) => DbPool };

        const pool = mysql.createPool({
          host: config.get<string>('DB_HOST'),
          port: config.get<number>('DB_PORT') ?? 3306,
          user: config.get<string>('DB_USER'),
          password: config.get<string>('DB_PASSWORD'),
          database: config.get<string>('DB_NAME'),
          // Pool sizing
          connectionLimit: config.get<number>('DB_POOL_MAX') ?? 20,
          // mysql2 uses waitForConnections + queueLimit instead of min/acquireTimeout
          waitForConnections: true,
          queueLimit: 50,
          // Idle / acquire timeouts (ms)
          idleTimeout: 30_000,
          connectTimeout: 5_000,
          // Keep connections alive
          enableKeepAlive: true,
          keepAliveInitialDelay: 10_000,
          // Timezone
          timezone: '+00:00',
          // Return dates as strings to avoid timezone conversion
          dateStrings: false,
          // Decode BINARY columns as Buffer
          supportBigNumbers: true,
          bigNumberStrings: false,
        });

        MysqlModule.pool = pool;

        // Wrap pool with circuit breaker (Req 15.1)
        // MySQL: 5000ms timeout / 50% error threshold / 10 min requests / 30s reset
        const cb = new CircuitBreaker(CIRCUIT_BREAKER_CONFIGS.mysql);
        const wrappedPool: DbPool = {
          execute: <T>(sql: string, params?: unknown[]) =>
            cb.execute(() => pool.execute<T>(sql, params)) as Promise<[T, unknown]>,
          getConnection: () => cb.execute(() => pool.getConnection()) as Promise<DbConnection>,
          end: () => pool.end(),
        };

        return wrappedPool;
      },
      inject: [ConfigService],
    };

    const transactionProvider: Provider = {
      provide: DB_TRANSACTION,
      useFactory: (pool: DbPool): TransactionFactory => {
        return async <T>(fn: (conn: DbTransaction) => Promise<T>): Promise<T> => {
          const conn = await pool.getConnection();
          await conn.beginTransaction();
          try {
            const result = await fn(conn);
            await conn.commit();
            return result;
          } catch (err) {
            await conn.rollback();
            throw err;
          } finally {
            conn.release();
          }
        };
      },
      inject: [MYSQL_POOL],
    };

    return {
      module: MysqlModule,
      providers: [poolProvider, transactionProvider],
      exports: [MYSQL_POOL, DB_TRANSACTION],
      global: true,
    };
  }

  async onApplicationShutdown(): Promise<void> {
    if (MysqlModule.pool) {
      await MysqlModule.pool.end();
      MysqlModule.pool = null;
    }
  }
}
