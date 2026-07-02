'use strict';

const express = require('express');
const db      = require('../db');
const { sendEmail } = require('../services/emailService');
const { loginLimiter, authLimiter } = require('../middleware/rateLimits');
const {
    createLoginToken, validateLoginToken,
    createSession, deleteSession,
    sessionCookieHeader, clearCookieHeader,
} = require('../services/sessionService');

const router = express.Router();

// POST /api/v1/login — send magic link
router.post('/api/v1/login', loginLimiter, async (req, res) => {
    const email = (req.body?.email || '').trim().toLowerCase().slice(0, 254);
    if (!email) return res.status(400).json({ error: 'email is required' });

    // Always return the same message to prevent email enumeration
    const ok = { message: 'If that email is registered, a login link is on its way (valid 15 minutes).' };

    try {
        const { rows } = await db.query(
            'SELECT id FROM organizations WHERE email = $1',
            [email]
        );
        if (!rows.length) return res.json(ok);

        const token    = await createLoginToken(rows[0].id);
        const appUrl   = process.env.APP_URL || 'https://api.sbomix.com';
        const loginUrl = `${appUrl}/auth?token=${token}`;

        await sendEmail({
            to:      email,
            subject: 'Your SBOMix login link',
            html: `
<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d1117;color:#e6edf3;padding:40px 20px;max-width:520px;margin:0 auto">
  <img src="${appUrl}/sbomix-logo.png" alt="SBOMix" style="height:32px;margin-bottom:28px" onerror="this.style.display='none'">
  <h2 style="margin:0 0 8px;font-size:22px">Sign in to SBOMix</h2>
  <p style="color:#8b949e;margin:0 0 28px">Click the button below to sign in. This link expires in 15 minutes and can only be used once.</p>
  <a href="${loginUrl}" style="display:inline-block;background:#238636;color:#fff;padding:12px 24px;border-radius:6px;font-weight:600;text-decoration:none;font-size:15px">Sign in to dashboard</a>
  <p style="color:#8b949e;font-size:12px;margin-top:24px">If you didn't request this, you can safely ignore it. Your account has not been accessed.</p>
  <p style="color:#484f58;font-size:11px;margin-top:8px">Link: ${loginUrl}</p>
</div>`,
        });

        res.json(ok);
    } catch (err) {
        console.error('[session/login]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /auth?token=... — validate magic link, create session, redirect to dashboard
router.get('/auth', authLimiter, async (req, res) => {
    const { token } = req.query;
    if (!token || typeof token !== 'string' || token.length > 100) {
        return res.redirect('/login?error=invalid');
    }
    try {
        const orgId = await validateLoginToken(token);
        if (!orgId) return res.redirect('/login?error=expired');

        const sessionToken = await createSession(orgId);
        res.setHeader('Set-Cookie', sessionCookieHeader(sessionToken));
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('Referrer-Policy', 'no-referrer');
        // Serve a micro-page that strips the ?token= from the URL via
        // history.replaceState so the token never appears in the browser
        // Referer header or nginx logs for subsequent requests.
        res.send(
            '<!DOCTYPE html><html><head><meta charset="utf-8">' +
            '<script>history.replaceState(null,"","/auth");' +
            'window.location.replace("/dashboard");</script>' +
            '</head><body></body></html>'
        );
    } catch (err) {
        console.error('[session/auth]', err.message);
        res.redirect('/login?error=server');
    }
});

// DELETE /api/v1/session — logout
router.delete('/api/v1/session', async (req, res) => {
    try { await deleteSession(req.headers.cookie); } catch { /* best effort */ }
    res.setHeader('Set-Cookie', clearCookieHeader());
    res.json({ ok: true });
});

module.exports = router;
