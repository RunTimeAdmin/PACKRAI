'use strict';

const fs = require('fs');

const SECRET_PATTERNS = /\b(password|passwd|secret|token|api_key|apikey|auth_key|private_key|access_key|credentials?|auth_secret|db_pass|database_password)\b/i;

/**
 * Parse a Dockerfile and return base image refs + security findings.
 *
 * @param {string} filePath - absolute path to the Dockerfile
 * @returns {{ path, baseImages, hasMultiStage, hasUser, hasHealthcheck, findings, summary }}
 */
function parseDockerfile(filePath) {
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');

    const findings = [];
    const baseImages = [];
    let hasUser = false;
    let hasHealthcheck = false;
    let fromCount = 0;

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        const lineNo = i + 1;

        if (!line || line.startsWith('#')) continue;

        if (/^FROM\s+/i.test(line)) {
            fromCount++;
            // FROM [--platform=...] <image>[:tag][@digest] [AS name]
            const m = line.match(/^FROM\s+(?:--\S+\s+)*(\S+)/i);
            if (m) {
                const imageRef = m[1];
                if (imageRef.toLowerCase() !== 'scratch') {
                    const parsed = parseImageRef(imageRef);
                    baseImages.push(parsed);

                    if (!parsed.tag && !parsed.digest) {
                        findings.push({
                            severity: 'HIGH', rule: 'unpinned-base-image', line: lineNo,
                            message: `Base image '${parsed.name}' has no tag — resolves to :latest`,
                        });
                    } else if (parsed.tag === 'latest') {
                        findings.push({
                            severity: 'HIGH', rule: 'unpinned-base-image', line: lineNo,
                            message: `Base image '${parsed.name}:latest' is non-deterministic — pin to a specific version`,
                        });
                    } else if (!parsed.digest) {
                        findings.push({
                            severity: 'MEDIUM', rule: 'no-digest-pin', line: lineNo,
                            message: `Base image '${parsed.name}:${parsed.tag}' has no digest pin — image can change on re-pull`,
                        });
                    }
                }
            }
        } else if (/^USER\s+/i.test(line)) {
            hasUser = true;
            const m = line.match(/^USER\s+(\S+)/i);
            if (m) {
                const user = m[1].split(':')[0];
                if (user === 'root' || user === '0') {
                    findings.push({
                        severity: 'HIGH', rule: 'explicit-root-user', line: lineNo,
                        message: 'Container explicitly runs as root — use a non-root USER',
                    });
                }
            }
        } else if (/^HEALTHCHECK\s+/i.test(line)) {
            hasHealthcheck = true;
        } else if (/^ADD\s+/i.test(line)) {
            const m = line.match(/^ADD\s+(.+)/i);
            if (m) {
                const args = m[1].trim();
                if (!args.match(/^https?:\/\//) && !args.match(/\.(tar|tgz|tar\.gz|tar\.bz2|tar\.xz|zip)\s/i)) {
                    findings.push({
                        severity: 'LOW', rule: 'add-instead-of-copy', line: lineNo,
                        message: 'Use COPY instead of ADD for plain file copies — ADD has unexpected side effects',
                    });
                }
            }
        } else if (/^(ENV|ARG)\s+/i.test(line) && SECRET_PATTERNS.test(line)) {
            const directive = /^ENV/i.test(line) ? 'ENV' : 'ARG';
            findings.push({
                severity: 'HIGH', rule: 'secret-in-env', line: lineNo,
                message: `Possible secret in ${directive} — use Docker build secrets or runtime env injection`,
            });
        }
    }

    if (!hasUser) {
        findings.push({
            severity: 'MEDIUM', rule: 'no-user-directive', line: null,
            message: 'No USER directive — container will run as root by default',
        });
    }
    if (!hasHealthcheck) {
        findings.push({
            severity: 'LOW', rule: 'no-healthcheck', line: null,
            message: 'No HEALTHCHECK directive — orchestrators cannot detect unhealthy containers',
        });
    }

    const high   = findings.filter((f) => f.severity === 'HIGH').length;
    const medium = findings.filter((f) => f.severity === 'MEDIUM').length;
    const low    = findings.length - high - medium;

    return {
        path: filePath,
        baseImages,
        hasMultiStage: fromCount > 1,
        hasUser,
        hasHealthcheck,
        findings,
        summary: { high, medium, low },
    };
}

/**
 * Parse a Docker image reference: name[:tag][@digest]
 * Handles registries with ports (registry.io:5000/name:tag).
 */
function parseImageRef(imageRef) {
    let digest = null;
    let ref = imageRef;

    const atIdx = imageRef.indexOf('@');
    if (atIdx !== -1) {
        digest = imageRef.slice(atIdx + 1);
        ref = imageRef.slice(0, atIdx);
    }

    // Tag colon must appear after the last '/' to avoid matching registry:port
    const slashIdx = ref.lastIndexOf('/');
    const colonIdx = ref.lastIndexOf(':');
    let name, tag;
    if (colonIdx !== -1 && colonIdx > slashIdx) {
        name = ref.slice(0, colonIdx);
        tag  = ref.slice(colonIdx + 1);
    } else {
        name = ref;
        tag  = null;
    }

    return { name, tag: tag || null, digest: digest || null, raw: imageRef };
}

module.exports = { parseDockerfile };
