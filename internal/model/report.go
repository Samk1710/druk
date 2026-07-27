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
}
