import { Module, Global } from '@nestjs/common';
import * as mysql from 'mysql2/promise';

@Global()
@Module({
  providers: [
    {
      provide: 'WRITER_POOL',
      useFactory: async () => {
        const pool = mysql.createPool({
          host: process.env.MYSQL_HOST || 'localhost',
          user: process.env.MYSQL_USER || 'uicp',
          password: process.env.MYSQL_PASSWORD || 'password',
          database: process.env.MYSQL_DB || 'uicp',
          port: parseInt(process.env.MYSQL_PORT || '3306', 10),
          waitForConnections: true,
          connectionLimit: 10, // Writer pool limit
          queueLimit: 0
        });

        // Wait for connection to ensure it's ready, or log warning
        try {
          const conn = await pool.getConnection();
          conn.release();
        } catch (error: any) {
           console.warn('WRITER_POOL initialization warning:', error.message);
        }

        return pool;
      }
    },
    {
      provide: 'READER_POOL',
      useFactory: async () => {
        // In a real environment, this connects to read-replicas.
        // Here we alias it to the same local instance.
        const pool = mysql.createPool({
          host: process.env.MYSQL_REPLICA_HOST || process.env.MYSQL_HOST || 'localhost',
          user: process.env.MYSQL_REPLICA_USER || process.env.MYSQL_USER || 'uicp',
          password: process.env.MYSQL_REPLICA_PASSWORD || process.env.MYSQL_PASSWORD || 'password',
          database: process.env.MYSQL_REPLICA_DB || process.env.MYSQL_DB || 'uicp',
          port: parseInt(process.env.MYSQL_REPLICA_PORT || process.env.MYSQL_PORT || '3306', 10),
          waitForConnections: true,
          connectionLimit: 20, // Reader pool often higher
          queueLimit: 0
        });

        try {
          const conn = await pool.getConnection();
          conn.release();
        } catch (error: any) {
           console.warn('READER_POOL initialization warning:', error.message);
        }

        return pool;
      }
    },
    {
      // Legacy alias to not break 500 existing repository files
      // Everything injected with 'MYSQL_POOL' defaults to WRITER_POOL for safety during refactor
      provide: 'MYSQL_POOL',
      useExisting: 'WRITER_POOL'
    }
  ],
  exports: ['WRITER_POOL', 'READER_POOL', 'MYSQL_POOL']
})
export class DatabaseModule {}
