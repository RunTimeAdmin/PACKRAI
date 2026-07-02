'use strict';

const crypto = require('crypto');
const db     = require('../db');

const SESSION_TTL_MS   = 24 * 60 * 60 * 1000; // 24h
const LOGIN_TOKEN_TTL_MS =      15 * 60 * 1000; // 15min

function hmac(token) {
    return crypto.createHmac('sha256', process.env.HMAC_SECRET).update(token).digest('hex');
}

function parseCookie(cookieHeader, name) {
    if (!cookieHeader) return null;
    for (const part of cookieHeader.split(';')) {
        const eqIdx = part.indexOf('=');
        if (eqIdx < 0) continue;
        if (part.slice(0, eqIdx).trim() === name) {
            return part.slice(eqIdx + 1).trim() || null;
        }
    }
    return null;
}

function sessionCookieHeader(token) {
    const secure = process.env.NODE_ENV !== 'development';
    return [
        `sbomix_session=${token}`,
        'HttpOnly',
        secure ? 'Secure' : null,
        'SameSite=Strict',
        `Max-Age=${SESSION_TTL_MS / 1000}`,
        'Path=/',
    ].filter(Boolean).join('; ');
}

function clearCookieHeader() {
    return 'sbomix_session=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/';
}

async function createLoginToken(orgId) {
    // Delete any existing unexpired token for this org so re-requests work cleanly
    await db.query(
        'DELETE FROM login_tokens WHERE org_id = $1',
        [orgId]
    );
    const token     = crypto.randomBytes(20).toString('hex');
    const expiresAt = new Date(Date.now() + LOGIN_TOKEN_TTL_MS);
    await db.query(
        `INSERT INTO login_tokens (org_id, token_hash, expires_at)
         VALUES ($1, $2, $3)`,
        [orgId, hmac(token), expiresAt]
    );
    return token;
}

async function validateLoginToken(token) {
    // Atomic DELETE … RETURNING: one-time use
    const { rows } = await db.query(
        `DELETE FROM login_tokens
         WHERE token_hash = $1 AND expires_at > NOW()
         RETURNING org_id`,
        [hmac(token)]
    );
    return rows[0]?.org_id || null;
}

async function createSession(orgId) {
    const token     = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
    await db.query(
        `INSERT INTO dashboard_sessions (org_id, token_hash, expires_at)
         VALUES ($1, $2, $3)`,
        [orgId, hmac(token), expiresAt]
    );
    return token;
}

async function validateSession(cookieHeader) {
    const token = parseCookie(cookieHeader, 'sbomix_session');
    if (!token) return null;
    const { rows } = await db.query(
        `SELECT org_id FROM dashboard_sessions
         WHERE token_hash = $1 AND expires_at > NOW()`,
        [hmac(token)]
    );
    return rows[0]?.org_id || null;
}

// Validate the session cookie and return the org row in a single round trip.
// Used by the auth middleware so the hot dashboard path does one query, not two.
async function validateSessionWithOrg(cookieHeader) {
    const token = parseCookie(cookieHeader, 'sbomix_session');
    if (!token) return null;
    const { rows } = await db.query(
        `SELECT o.id, o.name
         FROM dashboard_sessions s
         JOIN organizations o ON o.id = s.org_id
         WHERE s.token_hash = $1 AND s.expires_at > NOW()`,
        [hmac(token)]
    );
    return rows[0] || null;
}

async function deleteSession(cookieHeader) {
    const token = parseCookie(cookieHeader, 'sbomix_session');
    if (!token) return;
    await db.query(
        'DELETE FROM dashboard_sessions WHERE token_hash = $1',
        [hmac(token)]
    );
}


async function cleanupExpiredSessions() {
    try {
        const { rowCount: lt } = await db.query(
            `DELETE FROM login_tokens WHERE expires_at < NOW()`
        );
        const { rowCount: ds } = await db.query(
            `DELETE FROM dashboard_sessions WHERE expires_at < NOW()`
        );
        if (lt + ds > 0) {
            console.log(`[sessions] cleaned up ${lt} expired login token(s), ${ds} expired session(s)`);
        }
    } catch (err) {
        console.error('[sessions/cleanup]', err.message);
    }
}

function startSessionCleanup() {
    cleanupExpiredSessions();
    const timer = setInterval(cleanupExpiredSessions, 60 * 60 * 1000); // 1h
    if (timer.unref) timer.unref();
}

module.exports = {
    parseCookie,
    sessionCookieHeader,
    clearCookieHeader,
    createLoginToken,
    validateLoginToken,
    createSession,
    validateSession,
    validateSessionWithOrg,
    deleteSession,
    startSessionCleanup,
};
