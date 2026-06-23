'use strict';

const fs = require('fs');
const { createComponent } = require('../component');

/**
 * Parse Package.resolved (Swift Package Manager).
 *
 * Format v3 (Xcode 15+ / Swift 5.9+):
 *   {
 *     "pins": [
 *       { "identity": "swift-algorithms", "kind": "remoteSourceControl",
 *         "location": "https://github.com/apple/swift-algorithms",
 *         "state": { "revision": "<sha>", "version": "1.2.0" } }
 *     ],
 *     "version": 3
 *   }
 *
 * Format v1 (older Xcode):
 *   { "object": { "pins": [
 *       { "package": "swift-algorithms",
 *         "repositoryURL": "https://github.com/apple/swift-algorithms",
 *         "state": { "version": "1.2.0", "revision": "<sha>" } }
 *   ] }, "version": 1 }
 *
 * Package.resolved does not encode the dependency graph — only the flat
 * resolved set. All entries are treated as direct dependencies.
 * Pins without a semver "version" (branch-pinned) are skipped.
 */
function parseSwiftPackageResolved(filePath) {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));

    const pins = data.pins || data.object?.pins || [];
    const components = [];

    for (const pin of pins) {
        const identity = pin.identity || pin.package;
        const location = pin.location || pin.repositoryURL || '';
        const version  = pin.state?.version;

        // Skip branch/commit-only pins (no semver tag)
        if (!version) continue;

        // Build a host-qualified name from the repo URL: "github.com/apple/swift-algorithms"
        let name = identity;
        try {
            const url  = new URL(location);
            const repo = url.pathname.replace(/^\//, '').replace(/\.git$/, '');
            name = `${url.hostname}/${repo}`;
        } catch {
            // Use identity as fallback if URL is malformed
        }

        const comp = createComponent({
            name,
            version,
            ecosystem: 'swift',
            scope: 'required',
        });

        if (pin.state?.revision) {
            comp.hashes = [{ alg: 'SHA-1', content: pin.state.revision }];
        }

        components.push(comp);
    }

    return components;
}

module.exports = { parseSwiftPackageResolved };
