'use strict';

const crypto = require('crypto');
const db     = require('../db');

function hashApiKey(key) {
    return crypto.createHmac('sha256', process.env.HMAC_SECRET).update(key).digest('hex');
}

function generateApiKey() {
    return crypto.randomBytes(32).toString('hex');
}

const lastUsedCache = new Map();
const LAST_USED_TTL = 5 * 60 * 1000;
const LAST_USED_MAX = 10_000; // cap the cache so it can't grow without bound

function maybeUpdateLastUsed(keyHash) {
    const now = Date.now();
    if (now - (lastUsedCache.get(keyHash) || 0) < LAST_USED_TTL) return;
    // Simple bound: once the cache is full, clear it rather than leak memory.
    // Worst case is an extra last_used_at write per key after a flush.
    if (lastUsedCache.size >= LAST_USED_MAX) lastUsedCache.clear();
    lastUsedCache.set(keyHash, now);
    db.query('UPDATE api_keys SET last_used_at = NOW() WHERE key_hash = $1', [keyHash])
        .catch(() => {});
}

function requireScope(scope) {
    return async (req, res, next) => {
        try {
            // ── Bearer token takes priority (explicit API clients, CLI, Action) ──
            // Checked first so an explicit Authorization header always wins, even
            // in browser environments where a session cookie is also present.
            const header = req.headers.authorization || '';
            const key    = header.startsWith('Bearer ') ? header.slice(7).trim() : null;

            if (key) {
                const keyHash = hashApiKey(key);

                const { rows: keyRows } = await db.query(
                    `SELECT k.org_id, k.scopes, o.name AS org_name
                     FROM api_keys k
                     JOIN organizations o ON o.id = k.org_id
                     WHERE k.key_hash = $1 AND k.revoked_at IS NULL`,
                    [keyHash]
                );

                if (keyRows.length) {
                    const { org_id, scopes, org_name } = keyRows[0];
                    if (!scopes.includes(scope) && !scopes.includes('org:admin')) {
                        return res.status(403).json({
                            error: `Scope '${scope}' required`,
                            hint: `This key has scopes: ${scopes.join(', ')}`,
                        });
                    }
                    req.org    = { id: org_id, name: org_name };
                    req.scopes = scopes;
                    maybeUpdateLastUsed(keyHash);
                    return next();
                }

                // Legacy org-level key fallback
                const { rows: orgRows } = await db.query(
                    'SELECT id, name FROM organizations WHERE api_key = $1',
                    [keyHash]
                );
                if (orgRows.length) {
                    req.org    = orgRows[0];
                    req.scopes = ['org:admin'];
                    return next();
                }

                return res.status(401).json({ error: 'Invalid API key' });
            }

            // ── Session cookie (dashboard browser requests, no Bearer header) ──
            const { validateSessionWithOrg } = require('../services/sessionService');
            const org = await validateSessionWithOrg(req.headers.cookie);
            if (org) {
                req.org    = org;
                req.scopes = ['org:admin'];
                return next();
            }

            return res.status(401).json({ error: 'Missing Authorization header' });
        } catch (err) {
            console.error('[auth]', err.message);
            res.status(500).json({ error: 'Internal server error' });
        }
    };
}

module.exports = { hashApiKey, generateApiKey, requireScope };
