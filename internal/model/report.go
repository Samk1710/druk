package model

type RepoInfo struct {
	Language string
}

type Component struct {
	Name    string
	Version string
}

type SBOM struct {
	Components []Component
}

type Finding struct {
	ID         string
	Severity   string
	Package    string
	Version    string
	FixVersion string
}

type Report struct {
	Repo     RepoInfo
	SBOM     SBOM
	Findings []Finding
}
