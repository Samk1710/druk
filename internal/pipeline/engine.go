package pipeline

import (
	"fmt"
	"golang.org/x/sync/errgroup"

	"github.com/samk/druk/internal/agent"
	"github.com/samk/druk/internal/attacksurface"
	"github.com/samk/druk/internal/cve"
	"github.com/samk/druk/internal/model"
	"github.com/samk/druk/internal/reachability"
	"github.com/samk/druk/internal/repo"
	"github.com/samk/druk/internal/sbom"
	"github.com/samk/druk/internal/scan"
	"github.com/samk/druk/internal/secrets"
	"github.com/samk/druk/internal/supplychain"
	"github.com/samk/druk/internal/threatmodel"
)

// RunHeadless executes the security pipeline synchronously without a TUI.
func RunHeadless(target string, runSCA, runSAST, runSecrets, runNarrate bool) (*model.Report, error) {
	path, cleanup, err := repo.Load(target)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cleanup != nil {
			cleanup()
		}
	}()

	report := &model.Report{}
	report.Repo.Language = repo.DetectLanguage(path)

	var eg errgroup.Group
	var components []model.Component
	var findings []model.Finding
	var sastFindings []model.SASTFinding
	var secretFindings []model.SecretFinding
	var surface model.AttackSurface
	var cpgPath string
	var sc model.SupplyChain
	var tm model.ThreatModel

	if runSCA {
		eg.Go(func() error {
			components, _ = sbom.Generate(target)
			findings, _ = cve.QueryVulnerableCode(components)
			if len(findings) == 0 {
				findings, _ = cve.QueryOSV(components)
			}
			return nil
		})
	}

	if runSAST {
		eg.Go(func() error {
			sastFindings, _ = scan.RunSemgrep(target)
			return nil
		})
	}

	if runSecrets {
		eg.Go(func() error {
			secretFindings, _ = secrets.RunGitleaks(target)
			return nil
		})
	}

	eg.Go(func() error {
		surface, _ = attacksurface.Detect(target)
		return nil
	})

	if runSCA {
		eg.Go(func() error {
			cpgPath, _ = reachability.GenerateCPG(target, report.Repo.Language)
			return nil
		})
	}

	eg.Go(func() error {
		sc = supplychain.FetchScorecard(target)
		return nil
	})

	eg.Go(func() error {
		tm = threatmodel.Generate(target)
		return nil
	})

	if err := eg.Wait(); err != nil {
		return nil, fmt.Errorf("pipeline error: %v", err)
	}

	report.SBOM.Components = components
	report.Findings = findings
	report.SAST = sastFindings
	report.Secrets = secretFindings
	report.AttackSurface = surface
	report.SupplyChain = sc
	report.ThreatModel = tm

	if cpgPath != "" && len(report.Findings) > 0 {
		reachability.Analyze(report, cpgPath)
	}

	if runNarrate {
		report.AINarrative = agent.Synthesize(report)
	}

	return report, nil
}
