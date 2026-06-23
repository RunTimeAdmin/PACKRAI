'use strict';

const fs   = require('fs');
const yaml = require('yaml');
const { createComponent } = require('../component');

/**
 * Parse pubspec.lock (Dart / Flutter).
 *
 * Format:
 *   packages:
 *     http:
 *       dependency: "direct main"
 *       description:
 *         name: http
 *         sha256: "761a297c..."
 *         url: "https://pub.dev"
 *       source: hosted
 *       version: "1.1.0"
 *     flutter:
 *       dependency: "direct main"
 *       description: flutter
 *       source: sdk          ← skip: Flutter SDK itself, not a real dep
 *       version: "0.0.0"
 *
 * Dependency field values:
 *   "direct main"  → runtime dependency (scope: required)
 *   "direct dev"   → dev dependency (scope: optional)
 *   "transitive"   → transitive (scope: required)
 *
 * pubspec.lock does not encode the dependency graph. All entries are
 * included without a dependsOn list.
 */
function parsePubspecLock(filePath) {
    const data     = yaml.parse(fs.readFileSync(filePath, 'utf8'));
    const packages = data?.packages || {};
    const components = [];

    for (const [name, info] of Object.entries(packages)) {
        if (info.source === 'sdk') continue;      // skip Flutter/Dart SDK
        if (info.source !== 'hosted') continue;   // skip git/path sources

        const version = info.version;
        if (!version) continue;

        const dep   = String(info.dependency || '');
        const isDev = dep.includes('dev');
        const scope = isDev ? 'optional' : 'required';

        const comp = createComponent({
            name,
            version,
            ecosystem: 'pub',
            scope,
        });

        if (info.description?.sha256) {
            comp.hashes = [{ alg: 'SHA-256', content: info.description.sha256 }];
        }

        components.push(comp);
    }

    return components;
}

module.exports = { parsePubspecLock };
