#!/usr/bin/env node
'use strict';

/**
 * AI-BOM pipeline benchmark.
 *
 * Measures each stage of the AI-BOM pipeline against synthetic fixtures of
 * known sizes. No network calls, no Docker required — runs fully offline.
 *
 * Usage:
 *   node scripts/benchmark-aibom.js
 *   node scripts/benchmark-aibom.js --json     # machine-readable output
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const crypto = require('crypto');

const { detectAILocal, finalizeAIResult }  = require('../src/aibom');
const { hashWeightFile }                   = require('../src/parsers/aimodel');
const { generateCycloneDX }                = require('../src/generators/cyclonedx');
const { buildAIBomDocument }               = require('../src/ai/document');

const JSON_MODE = process.argv.includes('--json');

// ── Fixture builder ───────────────────────────────────────────────────────────

function buildFixture(root, weightSizeBytes) {
    const snap = path.join(root, 'models', 'llama', 'snap');
    fs.mkdirSync(snap, { recursive: true });
    fs.mkdirSync(path.join(root, '.cursor'), { recursive: true });
    fs.mkdirSync(path.join(root, 'prompts'), { recursive: true });

    // HuggingFace config.json
    fs.writeFileSync(path.join(snap, 'config.json'), JSON.stringify({
        _name_or_path: 'meta-llama/Llama-3.1-8B',
        model_type: 'llama',
        architectures: ['LlamaForCausalLM'],
        torch_dtype: 'bfloat16',
        hidden_size: 4096,
        num_hidden_layers: 32,
        vocab_size: 128256,
        max_position_embeddings: 8192,
        datasets: ['allenai/c4', 'tiiuae/falcon-refinedweb'],
    }));

    // Model weight file (deterministic content — same hash every run)
    const buf = Buffer.alloc(weightSizeBytes, 0x42);
    fs.writeFileSync(path.join(snap, 'model.safetensors'), buf);

    // MCP config with 4 servers (shell, broad-fs, remote, pinned)
    fs.writeFileSync(path.join(root, '.cursor', 'mcp.json'), JSON.stringify({
        mcpServers: {
            filesystem: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] },
            shell:      { command: 'bash', args: ['-c', 'x'] },
            remote:     { url: 'https://api.example.com/mcp', type: 'sse' },
            github:     { command: 'npx', args: ['@modelcontextprotocol/server-github@1.2.0'], env: { GITHUB_TOKEN: 'x' } },
        },
    }));

    // Prompt files
    fs.writeFileSync(path.join(root, 'prompts', 'system.prompt'), 'You are an agent.');
    fs.writeFileSync(path.join(root, 'CLAUDE.md'), '# rules');

    // Python lock file stand-in (AI framework packages)
    const pypiComps = [
        { name: 'torch',        version: '2.4.1', ecosystem: 'pypi' },
        { name: 'transformers', version: '4.44.0', ecosystem: 'pypi' },
        { name: 'langchain',    version: '0.2.16', ecosystem: 'pypi' },
        { name: 'openai',       version: '1.43.0', ecosystem: 'pypi' },
        { name: 'vllm',         version: '0.5.4',  ecosystem: 'pypi' },
    ];
    return { pypiComps };
}

// ── Timer helper ──────────────────────────────────────────────────────────────

function time(label, fn) {
    const start = process.hrtime.bigint();
    const result = fn();
    const ms = Number(process.hrtime.bigint() - start) / 1_000_000;
    return { label, ms: +ms.toFixed(2), result };
}

// ── Formatting ────────────────────────────────────────────────────────────────

function fmt(ms) { return `${ms.toFixed(1)}ms`.padStart(9); }
function bar(ms, maxMs) {
    const width = Math.max(1, Math.round((ms / maxMs) * 30));
    return '█'.repeat(width);
}
function human(bytes) {
    if (bytes >= 1_073_741_824) return `${(bytes / 1_073_741_824).toFixed(0)} GB`;
    if (bytes >= 1_048_576)     return `${(bytes / 1_048_576).toFixed(0)} MB`;
    return `${(bytes / 1024).toFixed(0)} KB`;
}

// ── Main ──────────────────────────────────────────────────────────────────────

function main() {
    const jsonResults = [];

    if (!JSON_MODE) {
        console.log(`\n  PackrAI AI-BOM Benchmark  —  ${new Date().toISOString().slice(0, 10)}`);
        console.log(`  node ${process.version}  |  fully offline, no network calls\n`);
    }

    // ── Stage 1: overhead on a repo with NO AI artifacts ─────────────────────
    {
        const root = fs.mkdtempSync(path.join(os.tmpdir(), 'packrai-aibom-bench-empty-'));
        // Only a package-lock.json so it's a valid project
        fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({
            name: 'plain-app', lockfileVersion: 3, packages: {},
        }));

        const r = time('detect (no AI artifacts)', () => {
            const raw = detectAILocal(root, []);
            return finalizeAIResult(raw);
        });

        if (!JSON_MODE) {
            console.log('  ── Stage 1: overhead on a plain project (no AI files) ──────────────────');
            console.log(`    ${r.label.padEnd(38)} ${fmt(r.ms)}  ${bar(r.ms, 200)}`);
            console.log(`    AI components found: ${r.result.components.length}`);
            console.log();
        }
        jsonResults.push({ stage: 'plain-project', ...r });
        fs.rmSync(root, { recursive: true, force: true });
    }

    // ── Stage 2: detection on a realistic AI project (small weight file) ──────
    const WEIGHT_SIZES = [
        { label: '1 MB weight',    bytes: 1 * 1024 * 1024 },
        { label: '100 MB weight',  bytes: 100 * 1024 * 1024 },
        { label: '1 GB weight',    bytes: 1024 * 1024 * 1024 },
    ];

    if (!JSON_MODE) {
        console.log('  ── Stage 2: detection + weight hashing at different model sizes ──────────');
    }

    for (const { label, bytes } of WEIGHT_SIZES) {
        const root = fs.mkdtempSync(path.join(os.tmpdir(), 'packrai-aibom-bench-'));
        const { pypiComps } = buildFixture(root, bytes);

        // Separate timing for walk vs hash
        const rDetect = time(`detect (${label})`, () =>
            detectAILocal(root, pypiComps, { hashWeights: false })
        );
        const rHash = time(`hash   (${label})`, () => {
            const weightPath = path.join(root, 'models', 'llama', 'snap', 'model.safetensors');
            return hashWeightFile(weightPath);
        });
        const rFinalize = time(`finalize (${label})`, () =>
            finalizeAIResult(rDetect.result)
        );

        const totalMs = rDetect.ms + rHash.ms + rFinalize.ms;
        const maxMs   = Math.max(rDetect.ms, rHash.ms, rFinalize.ms, 1);

        if (!JSON_MODE) {
            console.log(`    ${`detect  (${human(bytes)})`.padEnd(38)} ${fmt(rDetect.ms)}  ${bar(rDetect.ms, maxMs)}`);
            console.log(`    ${`hash    (${human(bytes)})`.padEnd(38)} ${fmt(rHash.ms)}  ${bar(rHash.ms, maxMs)}`);
            console.log(`    ${`finalize(${human(bytes)})`.padEnd(38)} ${fmt(rFinalize.ms)}  ${bar(rFinalize.ms, maxMs)}`);
            console.log(`    ${'total'.padEnd(38)} ${fmt(totalMs)}`);
            console.log(`    components: ${rFinalize.result.components.length}  threats: ${rFinalize.result.threats.length}  leastAgencyScore: ${rFinalize.result.stats.leastAgencyScore}`);
            console.log();
        }

        jsonResults.push({
            stage: `ai-project-${human(bytes).replace(' ', '')}`,
            weightBytes: bytes,
            detectMs: rDetect.ms,
            hashMs: rHash.ms,
            finalizeMs: rFinalize.ms,
            totalMs,
            components: rFinalize.result.components.length,
            threats: rFinalize.result.threats.length,
            leastAgencyScore: rFinalize.result.stats.leastAgencyScore,
        });

        fs.rmSync(root, { recursive: true, force: true });
    }

    // ── Stage 3: CycloneDX generation with AI components ─────────────────────
    {
        const root = fs.mkdtempSync(path.join(os.tmpdir(), 'packrai-aibom-bench-cdx-'));
        const { pypiComps } = buildFixture(root, 1024 * 1024); // 1MB fixture

        const detected  = detectAILocal(root, pypiComps, { hashWeights: false });
        const finalized = finalizeAIResult(detected);

        const rCDX = time('cyclonedx generation (with AI)', () =>
            generateCycloneDX(finalized.components, { name: 'my-ai-app', version: '1.0.0' })
        );

        if (!JSON_MODE) {
            console.log('  ── Stage 3: CycloneDX output generation ────────────────────────────────');
            console.log(`    ${'generate CycloneDX (AI components)'.padEnd(38)} ${fmt(rCDX.ms)}  ${bar(rCDX.ms, 100)}`);
            console.log(`    specVersion: ${rCDX.result.specVersion}  components in BOM: ${rCDX.result.components.length}`);
            console.log();
        }
        jsonResults.push({ stage: 'cyclonedx-generation', ms: rCDX.ms, components: rCDX.result.components.length });
        fs.rmSync(root, { recursive: true, force: true });
    }

    // ── Stage 4: AI-BOM document assembly (lineage + compliance) ─────────────
    {
        const root = fs.mkdtempSync(path.join(os.tmpdir(), 'packrai-aibom-bench-doc-'));
        const { pypiComps } = buildFixture(root, 1024 * 1024);

        const detected  = detectAILocal(root, pypiComps, { hashWeights: false });
        const finalized = finalizeAIResult(detected);

        const rDoc = time('aibom document (lineage + compliance)', () =>
            buildAIBomDocument({
                aiComponents: finalized.components,
                threats:      finalized.threats,
                meta:         { name: 'my-ai-app', version: '1.0.0' },
                keys:         null,
                agentic:      finalized.agentic || null,
            })
        );

        if (!JSON_MODE) {
            console.log('  ── Stage 4: AI-BOM document assembly ───────────────────────────────────');
            console.log(`    ${'lineage + compliance + attestation'.padEnd(38)} ${fmt(rDoc.ms)}  ${bar(rDoc.ms, 100)}`);
            const doc = rDoc.result;
            if (doc?.compliance?.controls) {
                const satisfied = doc.compliance.controls.filter(c => c.status === 'satisfied').length;
                console.log(`    controls satisfied: ${satisfied}/${doc.compliance.controls.length}  lineage records: ${doc.lineage?.length ?? 0}`);
            }
            console.log();
        }
        jsonResults.push({ stage: 'aibom-document', ms: rDoc.ms });
        fs.rmSync(root, { recursive: true, force: true });
    }

    // ── Summary ───────────────────────────────────────────────────────────────
    if (JSON_MODE) {
        console.log(JSON.stringify(jsonResults, null, 2));
    } else {
        // Derive hashing throughput from 1GB result
        const gbResult = jsonResults.find(r => r.stage === 'ai-project-1GB');
        if (gbResult) {
            const throughputMBps = (1024 / (gbResult.hashMs / 1000)).toFixed(0);
            console.log(`  Hashing throughput: ~${throughputMBps} MB/s (streaming SHA-256, 1MB buffer)`);
        }
        console.log(`\n  Note: Hub enrichment (HuggingFace API) is network-bound and not benchmarked`);
        console.log(`        here. Run with --no-aibom-enrich to stay on the fast local path.\n`);
    }
}

main();
