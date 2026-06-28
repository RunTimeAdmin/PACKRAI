'use strict';

const crypto  = require('crypto');
const express = require('express');
const db      = require('../db');
const { generateApiKey, hashApiKey } = require('../middleware/auth');
const { createSession, sessionCookieHeader } = require('../services/sessionService');
const { sendEmail } = require('../services/emailService');
const keysRepo = require('../repositories/keysRepo');

const router = express.Router();

const CLIENT_ID     = process.env.GITHUB_CLIENT_ID;
const CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const APP_URL       = process.env.APP_URL || 'https://api.sbomix.com';
const CALLBACK_URL  = `${APP_URL}/auth/github/callback`;

// In-memory CSRF state store — single-process, 10 min TTL
const _states  = new Map();
const STATE_TTL = 10 * 60 * 1000;

function newState() {
    // Evict stale entries
    const cutoff = Date.now() - STATE_TTL;
    for (const [k, ts] of _states) if (ts < cutoff) _states.delete(k);
    const s = crypto.randomBytes(16).toString('hex');
    _states.set(s, Date.now());
    return s;
}

function consumeState(s) {
    if (typeof s !== 'string' || !_states.has(s)) return false;
    const ts = _states.get(s);
    _states.delete(s);
    return Date.now() - ts < STATE_TTL;
}

// GET /auth/github — kick off OAuth flow
router.get('/auth/github', (_req, res) => {
    if (!CLIENT_ID) return res.redirect('/login?error=github_not_configured');
    const url = new URL('https://github.com/login/oauth/authorize');
    url.searchParams.set('client_id',    CLIENT_ID);
    url.searchParams.set('redirect_uri', CALLBACK_URL);
    url.searchParams.set('scope',        'read:user user:email');
    url.searchParams.set('state',        newState());
    res.redirect(url.toString());
});

// GET /auth/github/callback — exchange code, find-or-create org, set session
router.get('/auth/github/callback', async (req, res) => {
    const { code, state, error } = req.query;

    if (error || typeof code !== 'string' || !consumeState(state)) {
        return res.redirect(error === 'access_denied'
            ? '/login'
            : '/login?error=invalid');
    }

    try {
        // Exchange code for access token
        const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
            method:  'POST',
            headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
            body:    JSON.stringify({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET, code, redirect_uri: CALLBACK_URL }),
        });
        const tokenData = await tokenRes.json();
        if (!tokenData.access_token) {
            console.error('[github-auth] no access_token:', tokenData);
            return res.redirect('/login?error=github_token');
        }

        const ghHeaders = {
            'Authorization': `Bearer ${tokenData.access_token}`,
            'Accept':        'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
        };

        // Fetch profile and emails in parallel
        const [userRes, emailsRes] = await Promise.all([
            fetch('https://api.github.com/user',        { headers: ghHeaders }),
            fetch('https://api.github.com/user/emails', { headers: ghHeaders }),
        ]);
        const [ghUser, ghEmails] = await Promise.all([userRes.json(), emailsRes.json()]);

        const githubId    = String(ghUser.id);
        const githubLogin = ghUser.login || 'github-user';
        const emails      = Array.isArray(ghEmails) ? ghEmails : [];
        const primary     = emails.find(e => e.primary && e.verified)
                         || emails.find(e => e.verified)
                         || null;
        const email       = primary?.email || ghUser.email || null;

        // find-or-create org, then set session
        // Returns { orgId, newApiKey } — newApiKey is only set for brand-new orgs
        const { orgId, newApiKey } = await db.tx(async (client) => {
            // 1. Returning GitHub user
            {
                const { rows } = await client.query(
                    'SELECT id FROM organizations WHERE github_id = $1',
                    [githubId],
                );
                if (rows.length) return { orgId: rows[0].id, newApiKey: null };
            }

            // 2. Existing email account — bind github_id
            if (email) {
                const { rows } = await client.query(
                    'SELECT id FROM organizations WHERE email = $1',
                    [email],
                );
                if (rows.length) {
                    await client.query(
                        'UPDATE organizations SET github_id = $1 WHERE id = $2',
                        [githubId, rows[0].id],
                    );
                    return { orgId: rows[0].id, newApiKey: null };
                }
            }

            // 3. New org — generate key now so we can email the plaintext after commit
            const apiKey  = generateApiKey();
            const keyHash = hashApiKey(apiKey);
            const orgName = githubLogin;
            const { rows } = await client.query(
                `INSERT INTO organizations (name, email, api_key, github_id, plan, trial_ends_at)
                 VALUES ($1, $2, $3, $4, 'trial', NOW() + interval '14 days')
                 RETURNING id`,
                [orgName, email, keyHash, githubId],
            );
            const newOrgId = rows[0].id;
            await keysRepo.createKey(client, newOrgId, 'initial', keyHash, ['org:admin']);
            return { orgId: newOrgId, newApiKey: apiKey };
        });

        // Email API key to new orgs — best effort, don't block redirect
        if (newApiKey && email) {
            sendEmail({
                to:      email,
                subject: 'Your SBOMix API Key',
                html: `
<!DOCTYPE html><html><body style="background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:40px;max-width:560px;margin:0 auto">
<h1 style="font-size:22px;font-weight:700;margin-bottom:6px">Welcome to <span style="color:#3fb950">SBOMix</span></h1>
<p style="color:#8b949e;margin-bottom:28px">You signed in with GitHub. Here is your API key.</p>
<p style="margin-bottom:10px;font-weight:600">Your API key</p>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;font-family:monospace;font-size:13px;word-break:break-all;color:#3fb950;margin-bottom:6px">${newApiKey}</div>
<p style="color:#8b949e;font-size:12px;margin-bottom:28px">Save this key — it won't be shown again.</p>
<p><a href="${APP_URL}/dashboard" style="background:#238636;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600">Open dashboard</a></p>
</body></html>`,
            }).catch(() => {});
        } else if (newApiKey) {
            // New org but no email (GitHub user with private email) — show key on dashboard
            // Key is accessible from the dashboard key-management page
        }

        const sessionToken = await createSession(orgId);
        res.setHeader('Set-Cookie', sessionCookieHeader(sessionToken));
        res.setHeader('Referrer-Policy', 'no-referrer');
        // Strip GitHub params from URL before landing on dashboard
        res.send(
            '<!DOCTYPE html><html><head><meta charset="utf-8">' +
            '<script>history.replaceState(null,"","/auth");window.location.replace("/dashboard");</script>' +
            '</head><body></body></html>',
        );
    } catch (err) {
        console.error('[github-auth]', err.message);
        res.redirect('/login?error=server');
    }
});

module.exports = router;
