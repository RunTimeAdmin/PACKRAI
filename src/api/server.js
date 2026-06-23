'use strict';

require('dotenv').config();
const crypto     = require('crypto');
const express    = require('express');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const db         = require('./db');

// ── Startup guard ─────────────────────────────────────────────────────────────
if (!process.env.HMAC_SECRET) {
    console.error('[packrai] HMAC_SECRET env var is required. Generate one with:\n' +
        '  node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
    process.exit(1);
}

const app = express();

// ── Security headers ──────────────────────────────────────────────────────────
app.use(helmet());
app.disable('x-powered-by');

// ── Body parser ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));

// ── Rate limiting ─────────────────────────────────────────────────────────────
// General API limit: 120 requests / 15 min per IP
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests' },
});

// Stricter limit on ingest: 30 per minute (SBOM uploads are expensive)
const ingestLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Ingest rate limit exceeded' },
});

app.use('/api/', apiLimiter);

// ── API key helpers ───────────────────────────────────────────────────────────
// Keys are stored as HMAC-SHA256(key, HMAC_SECRET) — plaintext never persisted.
function hashApiKey(key) {
    return crypto.createHmac('sha256', process.env.HMAC_SECRET).update(key).digest('hex');
}

// ── Auth middleware ───────────────────────────────────────────────────────────
async function requireAuth(req, res, next) {
    const header = req.headers.authorization || '';
    const key = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!key) return res.status(401).json({ error: 'Missing Authorization header' });

    try {
        const { rows } = await db.query(
            'SELECT id, name FROM organizations WHERE api_key = $1',
            [hashApiKey(key)]
        );
        if (!rows.length) return res.status(401).json({ error: 'Invalid API key' });
        req.org = rows[0];
        next();
    } catch (err) {
        console.error('[auth]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
}

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => res.json({ ok: true }));

// ── Ingest ────────────────────────────────────────────────────────────────────
// POST /api/v1/ingest
// Body: { app, version, commit, branch, cyclonedx, spdx, stats }
app.post('/api/v1/ingest', ingestLimiter, requireAuth, async (req, res) => {
    const { app: appName, version, commit, branch, cyclonedx, spdx, stats } = req.body;
    if (!appName || !cyclonedx) {
        return res.status(400).json({ error: 'app and cyclonedx are required' });
    }
    if (!Array.isArray(cyclonedx.components)) {
        return res.status(400).json({ error: 'cyclonedx.components must be an array' });
    }

    try {
        const sbomId = await db.tx(async (client) => {
            // Upsert application
            const appRes = await client.query(
                `INSERT INTO applications (org_id, name)
                 VALUES ($1, $2)
                 ON CONFLICT (org_id, name) DO UPDATE SET name = EXCLUDED.name
                 RETURNING id`,
                [req.org.id, appName]
            );
            const appId = appRes.rows[0].id;

            // Insert SBOM record
            const sbomRes = await client.query(
                `INSERT INTO sboms
                   (app_id, org_id, version, commit_sha, branch, cyclonedx, spdx,
                    component_count, vulnerability_count, critical_count,
                    quality_score, ecosystems, elapsed_ms, generated_at)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW())
                 RETURNING id`,
                [
                    appId, req.org.id, version, commit, branch,
                    cyclonedx, spdx || null,
                    stats?.totalComponents ?? 0,
                    stats?.vulnerabilities ?? 0,
                    stats?.critical ?? 0,
                    stats?.qualityScore ?? null,
                    stats?.ecosystems ?? [],
                    stats?.elapsedMs ?? null,
                ]
            );
            const sbomId = sbomRes.rows[0].id;

            // Build the set of direct dependencies from the root component's dependsOn.
            // In CycloneDX 1.6, metadata.component is the root; its entry in the
            // dependencies array lists what it directly depends on.
            const rootPurl    = cyclonedx.metadata?.component?.purl;
            const directPurls = new Set(
                cyclonedx.dependencies
                    ?.find(d => d.ref === rootPurl)
                    ?.dependsOn ?? []
            );

            // Upsert each component; build purl→id map for vuln linking
            const components   = cyclonedx.components;
            const purlToCompId = new Map();

            for (const comp of components) {
                if (!comp.purl) continue;

                const license = comp.licenses?.[0]?.license?.id
                    || comp.licenses?.[0]?.license?.name
                    || null;

                // Ecosystem derived from purl type segment: pkg:npm/... → npm
                const ecosystem = comp.purl.split(':')[1]?.split('/')[0] ?? 'unknown';

                const compRes = await client.query(
                    `INSERT INTO components (org_id, purl, name, version, ecosystem, license)
                     VALUES ($1,$2,$3,$4,$5,$6)
                     ON CONFLICT (org_id, purl) DO UPDATE
                       SET license = COALESCE(EXCLUDED.license, components.license)
                     RETURNING id`,
                    [req.org.id, comp.purl, comp.name, comp.version, ecosystem, license]
                );
                const compId = compRes.rows[0].id;
                purlToCompId.set(comp.purl, compId);

                await client.query(
                    `INSERT INTO sbom_components (sbom_id, component_id, scope, is_direct)
                     VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
                    [sbomId, compId, comp.scope ?? 'required', directPurls.has(comp.purl)]
                );
            }

            // Ingest top-level vulnerabilities (CycloneDX 1.6 spec)
            for (const v of (cyclonedx.vulnerabilities || [])) {
                const osvId  = v.id;
                const cveId  = v.advisories?.find(a => a.title?.startsWith('CVE-'))?.title
                            || (osvId?.startsWith('CVE-') ? osvId : null);
                const rating = v.ratings?.[0];

                for (const affected of (v.affects || [])) {
                    const compId = purlToCompId.get(affected.ref);
                    if (!compId) continue;

                    await client.query(
                        `INSERT INTO vulnerabilities
                           (component_id, org_id, osv_id, cve_id, severity, cvss_score, fixed_version, title)
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                         ON CONFLICT (component_id, osv_id) DO UPDATE
                           SET severity     = EXCLUDED.severity,
                               cvss_score   = EXCLUDED.cvss_score,
                               last_checked = NOW()`,
                        [compId, req.org.id, osvId, cveId,
                         rating?.severity?.toUpperCase() ?? null,
                         rating?.score ?? null,
                         null,
                         v.description || null]
                    );
                }
            }

            return sbomId;
        });

        res.status(201).json({ sbomId });
    } catch (err) {
        console.error('[ingest]', err.message);
        res.status(500).json({ error: 'Ingest failed' });
    }
});

// ── Apps ──────────────────────────────────────────────────────────────────────
// GET /api/v1/apps
app.get('/api/v1/apps', requireAuth, async (req, res) => {
    try {
        const { rows } = await db.query(
            `SELECT a.id, a.name, a.repo_url,
                    COUNT(s.id) AS sbom_count,
                    MAX(s.created_at) AS last_scanned,
                    (SELECT critical_count FROM sboms WHERE app_id = a.id ORDER BY created_at DESC LIMIT 1) AS critical_count
             FROM applications a
             LEFT JOIN sboms s ON s.app_id = a.id
             WHERE a.org_id = $1
             GROUP BY a.id ORDER BY a.name`,
            [req.org.id]
        );
        res.json({ apps: rows });
    } catch (err) {
        console.error('[apps]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/v1/apps/:name/sbom  — latest SBOM for an app
app.get('/api/v1/apps/:name/sbom', requireAuth, async (req, res) => {
    try {
        const { rows } = await db.query(
            `SELECT s.id, s.version, s.commit_sha, s.branch, s.component_count,
                    s.vulnerability_count, s.critical_count, s.quality_score,
                    s.ecosystems, s.elapsed_ms, s.created_at
             FROM sboms s
             JOIN applications a ON a.id = s.app_id
             WHERE a.org_id = $1 AND a.name = $2
             ORDER BY s.created_at DESC LIMIT 1`,
            [req.org.id, req.params.name]
        );
        if (!rows.length) return res.status(404).json({ error: 'App not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('[apps/sbom]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ── CVE Search ────────────────────────────────────────────────────────────────
// GET /api/v1/search?cve=CVE-2021-44228
// The killer query: "Where across ALL our apps are we exposed to this CVE?"
app.get('/api/v1/search', requireAuth, async (req, res) => {
    const { cve, osv } = req.query;
    const id = cve || osv;
    if (!id) return res.status(400).json({ error: 'Provide ?cve= or ?osv= parameter' });

    try {
        const { rows } = await db.query(
            `WITH latest AS (
               SELECT DISTINCT ON (app_id) id AS sbom_id, app_id, version, created_at
               FROM sboms WHERE org_id = $1
               ORDER BY app_id, created_at DESC
             )
             SELECT
               a.name           AS app,
               l.version        AS app_version,
               l.created_at     AS last_scanned,
               c.purl,
               c.name           AS component,
               c.version        AS component_version,
               v.osv_id,
               v.cve_id,
               v.severity,
               v.cvss_score,
               v.fixed_version,
               v.title
             FROM vulnerabilities v
             JOIN components c          ON c.id = v.component_id
             JOIN sbom_components sc    ON sc.component_id = c.id
             JOIN latest l              ON l.sbom_id = sc.sbom_id
             JOIN applications a        ON a.id = l.app_id
             WHERE v.org_id = $1
               AND (v.cve_id = $2 OR v.osv_id = $2)
             ORDER BY v.cvss_score DESC NULLS LAST, a.name`,
            [req.org.id, id]
        );
        res.json({ query: id, exposedApps: rows.length, results: rows });
    } catch (err) {
        console.error('[search]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ── Risk Report ───────────────────────────────────────────────────────────────
// GET /api/v1/report
app.get('/api/v1/report', requireAuth, async (req, res) => {
    try {
        const [topVulns, topApps, summary] = await Promise.all([
            db.query(
                `WITH latest_sboms AS (
                   SELECT DISTINCT ON (app_id) id AS sbom_id
                   FROM sboms WHERE org_id = $1 ORDER BY app_id, created_at DESC
                 )
                 SELECT v.cve_id, v.osv_id, v.severity, v.cvss_score, v.title,
                        COUNT(DISTINCT a.id) AS apps_affected
                 FROM vulnerabilities v
                 JOIN components c        ON c.id = v.component_id
                 JOIN sbom_components sc  ON sc.component_id = c.id
                 JOIN latest_sboms ls     ON ls.sbom_id = sc.sbom_id
                 JOIN sboms s             ON s.id = ls.sbom_id
                 JOIN applications a      ON a.id = s.app_id
                 WHERE v.org_id = $1 AND v.severity IN ('CRITICAL','HIGH')
                 GROUP BY v.cve_id, v.osv_id, v.severity, v.cvss_score, v.title
                 ORDER BY v.cvss_score DESC NULLS LAST, apps_affected DESC
                 LIMIT 10`,
                [req.org.id]
            ),
            db.query(
                `SELECT a.name, s.critical_count, s.vulnerability_count,
                        s.component_count, s.quality_score, s.created_at
                 FROM applications a
                 JOIN LATERAL (
                   SELECT * FROM sboms WHERE app_id = a.id ORDER BY created_at DESC LIMIT 1
                 ) s ON TRUE
                 WHERE a.org_id = $1
                 ORDER BY s.critical_count DESC, s.vulnerability_count DESC
                 LIMIT 10`,
                [req.org.id]
            ),
            db.query(
                `SELECT
                   COUNT(DISTINCT a.id)  AS total_apps,
                   COUNT(DISTINCT c.id)  AS unique_components,
                   COUNT(DISTINCT v.id)  AS total_vulnerabilities,
                   SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
                   SUM(CASE WHEN v.severity = 'HIGH'     THEN 1 ELSE 0 END) AS high
                 FROM applications a
                 LEFT JOIN sboms s        ON s.app_id = a.id
                 LEFT JOIN sbom_components sc ON sc.sbom_id = s.id
                 LEFT JOIN components c   ON c.id = sc.component_id
                 LEFT JOIN vulnerabilities v ON v.component_id = c.id
                 WHERE a.org_id = $1`,
                [req.org.id]
            ),
        ]);

        res.json({
            summary: summary.rows[0],
            topVulnerabilities: topVulns.rows,
            mostExposedApps: topApps.rows,
        });
    } catch (err) {
        console.error('[report]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ── Org provisioning (admin key only) ────────────────────────────────────────
// POST /api/v1/orgs   body: { name }
// Protected by ADMIN_KEY env var — never expose this endpoint publicly.
app.post('/api/v1/orgs', async (req, res) => {
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== process.env.ADMIN_KEY) {
        return res.status(403).json({ error: 'Forbidden' });
    }

    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'name is required' });

    try {
        // Generate plaintext key, store only its HMAC hash — plaintext shown once.
        const apiKey     = crypto.randomBytes(32).toString('hex');
        const apiKeyHash = hashApiKey(apiKey);

        const { rows } = await db.query(
            'INSERT INTO organizations (name, api_key) VALUES ($1, $2) RETURNING id, name',
            [name, apiKeyHash]
        );
        // Return plaintext key in the response — this is the only time it is visible.
        res.status(201).json({ ...rows[0], api_key: apiKey });
    } catch (err) {
        console.error('[orgs]', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3080;
app.listen(PORT, () => {
    process.stdout.write(`PackrAI API listening on :${PORT}\n`);
});

module.exports = app;
