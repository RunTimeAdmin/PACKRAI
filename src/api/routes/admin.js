'use strict';

const crypto  = require('crypto');
const express = require('express');
const db      = require('../db');
const { hashApiKey, generateApiKey } = require('../middleware/auth');

const router = express.Router();

// Constant-time comparison so the admin key can't be recovered byte-by-byte
// via response timing.
function adminKeyMatches(provided) {
    const expected = process.env.ADMIN_KEY;
    if (!provided || !expected) return false;
    const a = Buffer.from(String(provided));
    const b = Buffer.from(expected);
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
}

router.post('/api/v1/orgs', async (req, res) => {
    if (process.env.ENABLE_ADMIN_API !== 'true') {
        return res.status(404).json({ error: 'Not found' });
    }
    if (!adminKeyMatches(req.headers['x-admin-key'])) {
        return res.status(403).json({ error: 'Forbidden' });
    }

    const { name } = req.body;
    if (!name || typeof name !== 'string' || !name.trim()) {
        return res.status(400).json({ error: 'name must be a non-empty string' });
    }
    if (name.length > 200) {
        return res.status(400).json({ error: 'name must be 200 characters or fewer' });
    }

    try {
        const apiKey     = generateApiKey();
        const apiKeyHash = hashApiKey(apiKey);

        const { rows } = await db.query(
            'INSERT INTO organizations (name, api_key) VALUES ($1, $2) RETURNING id, name',
            [name, apiKeyHash]
        );
        res.status(201).json({ ...rows[0], api_key: apiKey });
    } catch (err) {
        console.error('[orgs]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;
