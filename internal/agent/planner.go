package agent

import (
	"encoding/json"
	"fmt"
)

// PipelineConfig defines which deterministic stages to run.
type PipelineConfig struct {
	RunSCA        bool   `json:"run_sca"`
	RunSAST       bool   `json:"run_sast"`
	RunSecrets    bool   `json:"run_secrets"`
	RunSidecar    bool   `json:"run_sidecar,omitempty"`
	Reasoning     string `json:"reasoning"`
}

// PlannerAgent configures the security pipeline based on repo metadata.
func PlannerAgent(client *LLMClient, language string, fileCount int) PipelineConfig {
	// Default configuration (fail-safe)
	defaultConfig := PipelineConfig{
		RunSCA:     true,
		RunSAST:    true,
		RunSecrets: true,
		Reasoning:  "Fallback to default: run all scanners.",
	}

	systemPrompt := `You are the Druk Planner Agent. Your job is to configure the security pipeline.
You will receive repository metadata. You must output a JSON object configuring which tools to run.
The available tools are:
- SCA (Software Composition Analysis + Reachability): Best for all projects, but can be slow on massive repos.
- SAST (Static Analysis): Great for Python/Go/JS.
- Secrets: Fast and should almost always be run.

Rules:
1. If the repository is very large (> 10000 files), you might want to skip SAST to save time.
2. If the language is unknown, run everything.
3. You MUST output ONLY valid JSON matching this schema:
{
  "run_sca": boolean,
  "run_sast": boolean,
  "run_secrets": boolean,
  "reasoning": string (brief explanation of your choice)
}`

	userPrompt := fmt.Sprintf("Repository Metadata:\nLanguage: %s\nFile Count: %d\n\nGenerate the pipeline configuration JSON.", language, fileCount)

	resp, err := client.Generate(systemPrompt, userPrompt)
	if err != nil {
		return defaultConfig
	}

	var config PipelineConfig
	if err := json.Unmarshal([]byte(resp), &config); err != nil {
		return defaultConfig
	}

	return config
}
