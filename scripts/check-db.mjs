import mysql from 'mysql2/promise';
const conn = await mysql.createConnection({ host: 'localhost', port: 3306, user: 'root', password: '123456789', database: 'uicp_db' });
const [users] = await conn.query('SELECT COUNT(*) as cnt FROM users');
const [ids] = await conn.query('SELECT COUNT(*) as cnt FROM identities');
const [outbox] = await conn.query('SELECT COUNT(*) as cnt FROM outbox_events');
console.log('Users:', users[0].cnt, '| Identities:', ids[0].cnt, '| Outbox:', outbox[0].cnt);
await conn.end();
