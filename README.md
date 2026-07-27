# Druk — Architecture

Single-binary Go CLI that scans a repository and determines which CVEs are actually reachable, not just which ones are present. SBOM, CVE intelligence, SAST, and secret detection are fused with a Code Property Graph (CPG) so vulnerability severity is adjusted by reachability rather than relying solely on CVSS. The LLM is limited to planning and report generation—it never produces findings.

## Why

Most SCA tools produce a list of known vulnerabilities. Very few determine whether the vulnerable function is actually reachable from code that an attacker can execute. That is the primary purpose of Druk. Everything else—SBOM generation, SAST, secret detection, and supply chain scoring—supports that objective.

---

## Pipeline

                         ┌──────────────┐
                         │  Ingestion   │  GitHub API / Local FS
                         │  (Required)  │  errgroup fan-out, ~2-4 API calls
                         └──────┬───────┘
                                │
                    ┌───────────┼────────────┬──────────────┐
                    ▼           ▼            ▼              ▼
               ┌────────┐  ┌────────┐  ┌───────────┐  ┌────────────┐
               │  SBOM  │  │  SAST  │  │  Secrets  │  │  Attack    │
               │ (Syft) │  │(Semgrep│  │(Gitleaks) │  │  Surface   │
               └───┬────┘  │+Regex) │  └───────────┘  └────────────┘
                   │        └────────┘
                   ▼
              ┌─────────┐
              │   CVE   │  OSV.dev + VulnerableCode + deps.dev
              │ Enrich  │  Dedup by GHSA/CVE/OSV-ID alias
              └────┬────┘
                   ▼
              ┌──────────────┐
              │ Reachability │  AppThreat Atom → CPG → taint query
              │  (The Point) │  Cached per commit hash
              └──────┬───────┘
                     ▼
              ┌──────────────┐
              │ Supply Chain │  OpenSSF Scorecard + Sigstore verify
              │    Score     │
              └──────┬───────┘
                     ▼
              ┌──────────────┐
              │ Synthesizer  │  LLM, optional, reads report only
              │  (LLM, Opt)  │  Writes narrative, never findings
              └──────┬───────┘
                     ▼
              report.json → TUI / Table / MD / SARIF

Boundaries between rows are synchronized with `errgroup.Wait()`. Every stage within a row executes concurrently.

---

## Why Deterministic-First

All findings originate from deterministic tools (Syft, OSV, Semgrep, Gitleaks, Atom, and Scorecard). The LLM layer operates only on the completed `Report` struct. It may generate summaries and prioritize existing findings, but it cannot introduce new CVEs or security issues.

Running with `--no-llm` (the default when no API key is configured) removes only the narrative layer. Every finding remains available and continues to be ranked by reachability. This design keeps the scanner fully auditable and ensures CI pipelines never depend on external LLM services.

---

## Reachability: The Core Differentiator

OSV and VulnerableCode identify whether a package version is affected by a CVE. That information is necessary but insufficient—many reported vulnerabilities exist in dead code paths or development dependencies that are never executed.

Druk uses AppThreat Atom to construct a Code Property Graph (CPG). For advisories that identify an affected symbol, it performs path queries from detected entry points (HTTP handlers, CLI arguments, queue consumers, etc.) to the vulnerable function.

Each vulnerability is classified as one of three outcomes:

* **Reachable**
* **Unreachable**
* **Unknown** (unsupported language or Atom unavailable)

Unsupported scenarios degrade gracefully and never block the scan.

On internal fixture repositories, reachability analysis consistently reduces the list of reported CVEs from approximately 40–50 down to only a handful requiring investigation. That reduction is the primary value the tool provides.

---


## Agents vs. "Agents"

The system contains only two LLM-powered components.

The **Planner** determines which optional stages should execute based on repository characteristics. It produces structured JSON and falls back to default behaviour if schema validation fails.

The **Synthesizer** converts the completed report into a human-readable summary and prioritized action list. Its output is validated against the report's finding IDs; references to non-existent findings trigger a retry before falling back to a deterministic template.

`druk chat` operates exclusively on the completed report through a constrained tool interface (`searchFindings`, `getCallPath`, and `getSBOMComponent`). The model has no direct access to source files or shell execution, preventing it from inventing vulnerabilities that were never detected.

Every other component in the pipeline is conventional Go code orchestrating deterministic analysis tools. Describing the entire pipeline as "AI agents" would be inaccurate; only two components use an LLM.

---

## Known Gaps

* Reachability analysis currently supports Go and JavaScript/TypeScript. Python and Java support will be added as AppThreat's CPG coverage matures.
* CPG construction is the slowest stage (20–60 seconds on a cold cache). Caching by commit hash significantly improves repeated scans, although the initial analysis of large repositories remains expensive.
* Supply chain scoring relies partly on OpenSSF Scorecard's public dataset. Repositories that have not yet been indexed receive a reduced set of supply chain signals.
