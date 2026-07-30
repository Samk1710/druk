# Druk

<p align="center">
  <img src="https://img.shields.io/badge/go-%2300ADD8.svg?style=for-the-badge&logo=go&logoColor=white" />
  <img src="https://img.shields.io/badge/Status-v1.0-brightgreen?style=for-the-badge" />
</p>

Druk is an agentic software supply chain and application security engine.

Most modern security tools generate a high volume of alerts for vulnerable dependencies. However, they rarely verify if the vulnerable function is actually called by the application code. This leads to alert fatigue and false positives.

Druk addresses this by combining SBOM generation, CVE enrichment, SAST, Secrets detection, and OpenSSF Supply Chain scoring with Code Property Graph reachability analysis. It filters out dormant vulnerabilities and uses a lightweight LLM agent system to synthesize a human-readable threat model and answer questions about the security posture of the application.

## Key Features

1. **Reachability Analysis:** Druk maps CVE findings against an AppThreat Code Property Graph. A critical CVE that is never imported or called gets demoted. A CVE reachable from an entrypoint (like an HTTP handler) gets flagged as a priority.
2. **Grounded Agentic AI:** Druk uses a multi-agent architecture (Planner -> Executor -> Synthesizer). The LLM is not given raw access to source code to prevent hallucination. It only receives the deterministic scan JSON.
3. **Offline Capable:** By setting `DRUK_LLM_PROVIDER=ollama`, the entire AI pipeline runs locally on your machine without sending code telemetry to external APIs.
4. **CI/CD Native:** Running `druk ci --fail-on reachable-critical` executes headlessly and returns a non-zero exit code to block a pull request only if a vulnerable dependency is actually reachable by an attacker.
5. **Interactive TUI:** Druk features a real-time Bubble Tea terminal user interface to visualize the scan phases as they occur.

## Architecture

Druk is designed around a deterministic core wrapped in an agentic shell. This ensures that findings are verifiable and not hallucinated by the LLM.

```text
       ┌────────────────────────┐
       │   User / CI Pipeline   │
       └───────────┬────────────┘
                   │  druk analyze
                   ▼
       ┌────────────────────────┐
       │      Planner Agent     │ (Determines scan depth & tools)
       └───────────┬────────────┘
                   │
  ┌────────────────▼──────────────────────────────────────────────┐
  │               DETERMINISTIC CORE PIPELINE                     │
  │                                                               │
  │  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐       │
  │  │  Syft SBOM   │   │ Semgrep SAST │   │   Gitleaks   │       │
  │  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘       │
  │         │                  │                  │               │
  │  ┌──────▼───────┐   ┌──────▼───────┐          │               │
  │  │ Vulnerable   │   │ Attack       │          │               │
  │  │ Code / OSV   │   │ Surface      │          │               │
  │  └──────┬───────┘   └──────┬───────┘          │               │
  │         │                  │                  │               │
  │         └────────┬─────────┘                  │               │
  │                  ▼                            │               │
  │           ┌─────────────┐                     │               │
  │           │  AppThreat  │ (Code Property      │               │
  │           │  atom (CPG) │  Graph generation)  │               │
  │           └──────┬──────┘                     │               │
  │                  │                            │               │
  │           ┌──────▼──────┐                     │               │
  │           │ Reachability│ (Validates call     │               │
  │           │  Analysis   │  paths to CVEs)     │               │
  │           └──────┬──────┘                     │               │
  │                  │                            │               │
  │           ┌──────▼──────┐                     │               │
  │           │  Severity   │ (Demotes dormant    │               │
  │           │ Re-Ranking  │  vulnerabilities)   │               │
  │           └──────┬──────┘                     │               │
  │                  │                            │               │
  └──────────────────┼────────────────────────────┼───────────────┘
                     │                            │
             ┌───────▼────────────────────────────▼───────┐
             │            CANONICAL JSON REPORT           │
             └───────┬────────────────────────────┬───────┘
                     │                            │
  ┌──────────────────▼────────────┐ ┌─────────────▼───────────────────┐
  │        AGENTIC AI SHELL       │ │         OUTPUT LAYER            │
  │                               │ │                                 │
  │ ┌───────────────────────────┐ │ │  ┌───────────────────────────┐  │
  │ │     Synthesizer Agent     │ │ │  │  JSON / SARIF Exporters   │  │
  │ │ (Writes Executive Summary │ │ │  │ (For GitHub Adv Security) │  │
  │ │  & STRIDE Threat Model)   │ │ │  └───────────────────────────┘  │
  │ └───────────────────────────┘ │ │                                 │
  │                               │ │  ┌───────────────────────────┐  │
  │ ┌───────────────────────────┐ │ │  │     Bubble Tea TUI        │  │
  │ │       Q&A Chat Agent      ├─┼─┼─►│ (Live interactive report  │  │
  │ │  (Grounded Tool-Calling)  │ │ │  │  with 7-pane dashboard)   │  │
  │ └───────────────────────────┘ │ │  └───────────────────────────┘  │
  └───────────────────────────────┘ └─────────────────────────────────┘
```

Druk implements a strict "Agentic Trinity":
1. **The Planner Agent:** Analyzes the repository metadata (language, file size) and outputs a structured JSON configuration determining which heavy scanners to run.
2. **The Synthesizer Agent:** Receives the deterministic JSON report and writes an executive summary and STRIDE threat model.
3. **The Q&A Agent:** A grounded tool-calling loop (using `search_findings`, `get_call_path`, `get_supply_chain_score`). It executes local Go functions to read the report rather than guessing, enforcing a strict token budget to prevent runaway loops.

### Supported LLM Providers
- **Groq:** (Default) Fast inference using `llama3-8b-8192`. Requires `DRUK_GROQ_API_KEY`.
- **Ollama:** (Local) Fully air-gapped security. Requires `DRUK_LLM_PROVIDER=ollama`.

## Installation

```bash
# Clone the repository
git clone https://github.com/Samk1710/druk.git
cd druk

# Build the binary
go build -o druk main.go
sudo mv druk /usr/local/bin/

# Check dependencies
druk setup
```

**Requirements:** Druk relies on standard scanners under the hood. You should have `syft` and `semgrep` installed in your path. The `druk setup` command will provide installation instructions if they are missing.

## Usage

### 1. The Interactive TUI
To scan a local repository using the terminal UI:
```bash
druk analyze . 
```

To run all scanners and let the AI Synthesizer summarize the findings (requires `DRUK_GROQ_API_KEY`):
```bash
druk analyze --all --narrate .
```

To let the Planner Agent automatically determine which scanners to run based on repository size:
```bash
druk analyze --auto .
```

### 2. CI/CD Mode (Headless)
To run Druk in a CI pipeline and fail the build if reachable vulnerabilities are found:
```bash
druk ci --fail-on reachable-critical .
```

### 3. Data Exports
Export the final report to JSON or SARIF (for GitHub Advanced Security):
```bash
druk analyze --output sarif > results.sarif
```

## License
MIT License.
