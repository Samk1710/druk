package model

type RepoInfo struct {
	Language string
}

type Component struct {
	Name    string
	Version string
	Purl    string
}

type SBOM struct {
	Components []Component
}

type Finding struct {
	ID           string
	Aliases      []string
	Severity     string
	Package      string
	Version      string
	FixVersion   string
	Reachability string   // "reachable", "unreachable", "unknown"
	CallPath     []string // trace of function calls or files
}

type SASTFinding struct {
	ID       string
	Message  string
	Severity string
	Path     string
	Line     int
}

type SecretFinding struct {
	RuleID      string
	Description string
	Severity    string
	Path        string
	Line        int
}

type Entrypoint struct {
	Path      string
	Line      int
	Framework string
}

type AttackSurface struct {
	Entrypoints []Entrypoint
}

type Report struct {
	Repo          RepoInfo
	SBOM          SBOM
	Findings      []Finding
	SAST          []SASTFinding
	Secrets       []SecretFinding
	AttackSurface AttackSurface
	SupplyChain   SupplyChain
	ThreatModel   ThreatModel
	AINarrative   AINarrative
}

type AINarrative struct {
	Summary            string   `json:"summary"`
	PrioritizedActions []string `json:"prioritized_actions"`
	ModelUsed          string   `json:"model_used"`
}

type SupplyChain struct {
	Score      float64
	Checks     []ScorecardCheck
	IsScorecard bool // true if we pulled from OpenSSF API
}

type ScorecardCheck struct {
	Name        string
	Score       int
	Reason      string
	Description string
}

type ThreatModel struct {
	Assets          []string
	TrustBoundaries []string
	STRIDE          []STRIDERisk
}

type STRIDERisk struct {
	Category    string // Spoofing, Tampering, etc.
	Description string
	Mitigation  string
}
