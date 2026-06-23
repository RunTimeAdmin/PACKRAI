'use strict';

const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 3000,
});

pool.on('error', (err) => {
    process.stderr.write(`[db] idle client error: ${err.message}\n`);
});

module.exports = {
    query:  (...args) => pool.query(...args),
    pool,

    /** Run fn(client) inside a transaction. Rolls back on throw. */
    async tx(fn) {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            const result = await fn(client);
            await client.query('COMMIT');
            return result;
        } catch (err) {
            await client.query('ROLLBACK');
            throw err;
        } finally {
            client.release();
        }
    },
};
