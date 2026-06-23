# PackrAI Roadmap: SBOM Platform for Enterprise

## Strategic Position

PackrAI is positioned at the **intersection of DevOps and enterprise security** — we own the intake layer and will extend into the layers that enterprises actually pay for: centralized SBOM management, CVE correlation, and network-exposed risk.

### What We're Building (Not Building)

| Layer | Our Play | Other Tools |
|-------|----------|------------|
| SBOM Generation | ✅ Fastest, most accurate (lock-file-first) | Syft, CycloneDX CLI |
| Normalization | ✅ Purl-based, consistent across formats | Ad-hoc |
| Central Repo + API | ✅ Building (Week 1-4) | Dependency-Track (OSS, weak) |
| Enrichment | ✅ OSV batch, severity mapping | Snyk, Black Duck |
| Runtime Validation | ❌ Out of scope v1 | Anchore, Wiz, Sysdig |
| CMDB Integration | ❌ Out of scope v1 (enterprise sales motion) | ServiceNow integrations |
| **Network Correlation** | ✅ **Your moat** (Weeks 12-24) | No one does this |
| Risk Engine | ✅ v1: simple scoring; v2: contextual (Weeks 8-12) | Every vendor claims this |
| Visualization | ⚠️ v1: API only; v2: dashboards (Weeks 12+) | Many |

---

## Architecture We're Building (vs. Ideal)

```
Ideal Enterprise SBOM Platform:

  Dev Pipelines
       ↓
  1️⃣ SBOM Generation      ✅ DONE (CLI + Action)
       ↓
  2️⃣ Ingestion/Normalization ✅ DONE (API)
       ↓
  3️⃣ Central Repository   ✅ BUILDING (Postgres + API)
       ↓
  4️⃣ Enrichment Layer     ✅ OSV built; CVE mapping ready
       ↓
  5️⃣ Runtime Validation   ❌ Not v1
       ↓
  6️⃣ CMDB Integration     ❌ Not v1
       ↓
  7️⃣ Network Correlation  ✅ ROADMAP (Q2 2026)
       ↓
  8️⃣ Risk & Analytics     ✅ v1 basic; v2 contextual (Q1 2026)
       ↓
  9️⃣ Visualization / API  ✅ API live; dashboards (Q2 2026)
```

---

## What the 15 Gaps Tell Us (Priority Mapping)

### Gaps PackrAI Directly Solves

| Gap | Status | When | Effort |
|-----|--------|------|--------|
| **Gap 3** — Flat dep trees | ✅ DONE | Now | - |
| **Gap 5** — Poor CVE correlation | ✅ v1 | Now | - |
| **Gap 14** — CI/CD overhead | ✅ DONE | Now | - |
| **Gap 4** — Format inconsistency | ✅ DONE | Now | - |
| **Gap 13** — No SBOM quality score | ✅ DONE | Now | - |
| **Gap 7** — Static SBOMs (not refreshed) | ✅ SOLVED | Action workflow | - |
| **Gap 6** — Scale & management | ✅ v1 (central API) | Week 3-4 | High |
| **Gap 8** — No enterprise integration | ⚠️ Roadmap | Q1-Q2 2026 | Medium |

### Gaps We Defer (Intentionally)

| Gap | Why | Timeline |
|-----|-----|----------|
| Gap 1 — Runtime/embedded visibility | Requires eBPF agents + container instrumentation; different product line | Beyond v1 |
| Gap 9 — Provenance/SLSA | Correct but immature ecosystem; do after GitHub Action is solid | Q2 2026 |
| Gap 10 — Binary/firmware | Binary analysis is a decade-long research problem | Way out |
| Gap 2 — Runtime context | Needs runtime correlation (Gap 5) | v2 after network layer |
| Gap 11 — Container layer complexity | Requires container-specific parsers + layer tracking | Q1 2026 |
| Gap 12 — License incompleteness | Can add registry API enrichment | Q1 2026 |
| Gap 15 — Lack of contextual prioritization | **THIS IS OUR NETWORK LAYER** | Q2 2026 |

---

## The Roadmap: 6 Quarters (18 Months)

### 🚀 **Q4 2024 — Foundation (Weeks 1-4)**

**Goal:** Platform is live and ingesting SBOMs from real teams.

#### Week 1-2: Deploy & Release
- [ ] Docker Compose for self-hosted API (Postgres + packrai-api)
- [ ] GitHub Action published as `packrai/sbom-action@v1`
- [ ] Deployment docs (AWS EC2, GCP, self-hosted)
- [ ] org provisioning script (`POST /api/v1/orgs`)

**Deliverable:** A team can deploy the stack in 15 minutes and start running the action.

#### Week 3: Integration Testing
- [ ] End-to-end test: GitHub Action → API ingest → search query
- [ ] Test multi-org isolation
- [ ] Test CVE search across 100+ apps
- [ ] Load test: 1000 SBOMs, query latency <1s

**Deliverable:** Platform is production-ready for closed beta.

#### Week 4: Closed Beta (Customers)
- [ ] Onboard 3-5 friendly customers
- [ ] Collect feedback on action workflow, API usability, missing fields
- [ ] Patch based on feedback

**Deliverable:** Real usage patterns; confidence that the core story works.

---

### 📊 **Q1 2025 — Risk Analytics v1 (Weeks 5-12)**

**Goal:** Risk scoring, compliance reporting, and deeper visibility.

#### Week 5-7: Risk Scoring Engine
- [ ] Risk score per component: `CVSS × exposure_weight × usage_weight`
- [ ] Exposure weight: `is_direct ? 1.5 : 1.0`
- [ ] Usage weight: tracked from GitHub Action context
- [ ] Scope: dev/optional dependencies reduce score 2x
- [ ] Implement `/api/v1/report` enhancements:
  - [ ] Risk-ranked vulnerability list
  - [ ] Apps by risk (not just critical count)
  - [ ] License compliance check (CISA-restricted licenses)

**Deliverable:** `GET /api/v1/report` returns actionable risk ranking.

#### Week 8-9: Compliance Reporting
- [ ] CISA 2025 minimum elements checklist
- [ ] SBOM completeness per app (quality score trend over time)
- [ ] License audit reports (GPL/AGPL detection, corporate policy check)
- [ ] PDF export: org risk dashboard + app summary

**Deliverable:** Exportable compliance reports for audits.

#### Week 10-12: Dashboards (Web UI v1)
- [ ] Simple React dashboard (Next.js)
- [ ] Home: org risk summary, top critical vulns
- [ ] Apps page: list, risk-ranked, last scan time
- [ ] CVE search: interactive results with affected apps
- [ ] SBOM timeline: version history per app

**Deliverable:** DevSecOps teams have a dashboard; executives can see compliance posture.

---

### 🌐 **Q2 2025 — Network Layer Foundation (Weeks 13-20)**

**Goal:** Connect SBOMs to network exposure (Gap 15 solved).

#### Week 13-14: Network Data Integration
- [ ] Design: FortiAnalyzer → PackrAI connector
  - [ ] API to ingest firewall flows (source IP → dest IP:port → action)
  - [ ] Map host IP → CMDB/inventory system
  - [ ] Schema additions: flows table, exposure classification
- [ ] Design: NetFlow/IPFIX connector
  - [ ] Parse flow records
  - [ ] Identify external-facing IPs

**Deliverable:** Network data can flow into PackrAI.

#### Week 15-16: Host-to-Component Mapping
- [ ] Integration with osquery/Wazuh/EDR agents
  - [ ] "What processes are running on host X?"
  - [ ] Map process → SBOM component
  - [ ] Table: host_id → component_id (many-to-many)
- [ ] Or: manual inventory upload (CSV: host, IP, SBOM version)

**Deliverable:** We know what's running on what hosts.

#### Week 17-20: Exposure Analytics
- [ ] New risk dimension: `is_exposed_externally`
  - [ ] Host IP has outbound flow to untrusted CIDR?
  - [ ] Port is internet-facing (not RFC1918)?
- [ ] New queries:
  - [ ] "Vulnerable lib X on exposed host Y"
  - [ ] "Critical CVE components talking to internet"
  - [ ] "Internal-only vulns (low real risk)"
- [ ] Dashboard: Network Exposure view

**Deliverable:** CISO's killer dashboard: "Here's what can be breached vs. what's internal."

---

### 🔐 **Q3 2025 — Trust & Provenance (Weeks 21-24)**

**Goal:** SBOMs are signed and verifiable.

#### Week 21-22: SBOM Signing
- [ ] GitHub Action: sign SBOMs with Sigstore (Cosign)
- [ ] Store public key in repo
- [ ] API: verify signature on ingest
- [ ] SLSA provenance v1.0 embedded in BOM metadata

**Deliverable:** SBOMs are tamper-evident.

#### Week 23-24: Vendor SBOM Validation
- [ ] Tool: validate incoming vendor SBOMs (from suppliers)
- [ ] Check: signature valid, elements complete, no stale data
- [ ] Dashboard: vendor SBOM compliance tracker

**Deliverable:** Procurement teams can vet supplier SBOMs.

---

### 🏗️ **Q4 2025 — Enterprise Integration (Weeks 25-28)**

**Goal:** Plug into customer's existing infrastructure.

#### Week 25-26: CMDB/ServiceNow Integration
- [ ] API: ServiceNow sync
  - [ ] SBOM app → ServiceNow CI (Configuration Item)
  - [ ] Risk score → Priority field
  - [ ] Ownership → Assignment group
- [ ] Bi-directional: ServiceNow ticket → PackrAI API notification

**Deliverable:** Tickets auto-create when new CVEs hit critical apps.

#### Week 27-28: Integrations Library
- [ ] Slack: daily risk digest
- [ ] Datadog/Splunk: log CVE ingestion
- [ ] PagerDuty: critical vulnerability alerts
- [ ] Jira: auto-create engineering tickets

**Deliverable:** Security ops integrated into team workflows.

---

## Near-Term Build Order (Next 8 Weeks)

### **Weeks 1-2: Deploy & Release** ⚡ START HERE

```
Files to write:
- docker-compose.yml (postgres + packrai-api)
- .env.example
- docs/deployment.md (AWS EC2 / GCP / self-hosted)
- docs/api.md (endpoints, auth, examples)
- GitHub Action release workflow (.github/workflows/publish-action.yml)

Effort: 3-4 days
Value: Live product in customers' hands
```

**Deliverables:**
- [ ] packrai-api Docker image pushes to GHCR
- [ ] action.yml published as `packrai/sbom-action@v1`
- [ ] Getting started guide (README update)
- [ ] API docs with curl examples

---

### **Weeks 3-4: Integration Testing & Beta**

```
Files to write:
- tests/api.integration.test.js (full flow: action → ingest → search)
- tests/fixtures/real-sbom-*.json (multi-ecosystem test data)
- scripts/load-test.js (1000+ SBOMs, query latency)
- scripts/beta-onboard.sh (org + team setup)

Effort: 2-3 days
Value: Confidence the platform works end-to-end
```

**Deliverables:**
- [ ] Full flow tested (GitHub → API → CVE search)
- [ ] Load test passes: <1s query on 1000 SBOMs
- [ ] 3-5 closed beta customers onboarded
- [ ] Feedback collected & prioritized

---

### **Weeks 5-8: Risk Scoring & Compliance (January 2025)**

```
Files to write:
- src/api/risk.js (scoring engine)
- src/api/compliance.js (CISA checklist, license audit)
- src/api/export.js (PDF generation)
- routes/api/v2/report.js (enhanced endpoints)

Effort: 4-5 days
Value: Risk is actionable; audits are provable
```

**Deliverables:**
- [ ] Risk score deployed in `/api/v1/report`
- [ ] CISA compliance checklist in API
- [ ] PDF export working (org report + app summary)
- [ ] Dashboard prototype in Figma (UI design)

---

## Success Metrics (18-Month Target)

| Metric | v1 (Q4 2024) | v2 (Q2 2025) |
|--------|------------|------------|
| **Adoption** | 10 closed-beta customers | 50+ paying customers |
| **SBOMs Ingested** | 500 | 50,000+ |
| **SBOM Freshness** | 7-day avg | <24h avg (CI/CD gated) |
| **CVE Search Latency** | <1s (100 apps) | <500ms (1000 apps) |
| **Network Exposure** | N/A | 10+ integrations (FAZ, Splunk, etc.) |
| **ARR** | $0 (beta) | $500K+ |

---

## Competitive Position at Each Stage

### Q4 2024
- Fastest SBOM generator + central repo
- Better than Syft standalone (we integrate with CI/CD)
- Comparable to Dependency-Track (but smaller, faster)

### Q2 2025
- Network correlation none of the incumbents have
- Wins: DevSecOps + CISO conversations
- Positioning: "SBOMs that show what can actually be breached"

### Q4 2025
- Enterprise-grade: provenance + CMDB + integrations
- Defensible because we own the intake layer
- Competitors: trying to retrofit network layers onto their tools

---

## Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Competitors release faster | We have a 6-month head start on CLI + action. Lock in GitHub adoption early. |
| Database scales poorly | Denormalize early (pre-compute risk scores), use read replicas, test at 1M components. |
| Network layer too complex | Start simple: manual IP-to-app mapping. Automate connectors one at a time. |
| Procurement: buying Snyk/Black Duck | Position us as the platform layer, not the scanner. Work with them (API integrations). |
| Open-source fork threat | Keep CLI open, monetize the platform (central API, compliance reports, dashboards). |

---

## Success Definition

**v1 Success (Q4 2024):** A team commits `packrai.yml` to their repo, SBOMs flow to our API, they can search "where is CVE-XXXX" and get a list of exposed apps.

**v2 Success (Q2 2025):** A CISO can see "which of our critical apps talk to the internet and have critical vulns" in one dashboard.

**v3 Success (Q4 2025):** Enterprises buy us instead of Snyk/Dependency-Track because we integrate with their entire security stack and give them the network-exposed risk story nobody else can.

---

## Next Decision: Where to Start?

**Option A (Recommended):** Build deployment + release first (Weeks 1-2)
- Get the GitHub Action in customers' hands ASAP
- Lock in "we're the standard SBOM generator for GitHub"
- Everything else builds on top of real SBOMs in production

**Option B:** Risk engine first (Weeks 5-8 in parallel)
- Build dashboards while action is being tested
- Show the vision to close beta customers
- Risk: complexity delays both tracks

**Option C:** Network layer start-to-finish (skip risk engine)
- Build the moat immediately
- Risk: takes 12+ weeks, platform isn't ready for data yet

**Recommendation:** Start with Option A. Deploy → Beta → Risk → Network. Sequential, de-risked, each stage validates the previous one.

