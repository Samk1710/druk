package tui

import (
	"fmt"
	"golang.org/x/sync/errgroup"
	"strings"
	"sync"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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
	"github.com/samk/druk/internal/agent"
)

type StatusMsg struct {
	Module string
	Status string
}

type State int

const (
	StateSelection State = iota
	StateScanning
	StateDone
)

type ScannerOption struct {
	Name     string
	Selected bool
}

type RepoLoadedMsg struct {
	Report  *model.Report
	Cleanup func()
}

type ErrorMsg error

type AppModel struct {
	target    string
	state     State
	spinner   spinner.Model
	quitting  bool
	err       error
	report    *model.Report
	dashboard dashboardModel
	options   []ScannerOption
	cursor    int
	statuses  *sync.Map
	narrate   bool
}

func InitialModel(target string, sca, sast, secrets, autoStart, narrate bool) AppModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	opts := []ScannerOption{
		{"SBOM & Vulnerabilities", sca},
		{"SAST (Semgrep)", sast},
		{"Secrets (Gitleaks)", secrets},
	}

	state := StateSelection
	if autoStart {
		state = StateScanning
	}

	return AppModel{
		target:   target,
		state:    state,
		spinner:  s,
		options:  opts,
		statuses: &sync.Map{},
		narrate:  narrate,
	}
}

func (m AppModel) Init() tea.Cmd {
	if m.state == StateScanning {
		return tea.Batch(m.spinner.Tick, m.loadRepoCmd)
	}
	return nil
}

func (m AppModel) loadRepoCmd() tea.Msg {
	runSBOM := m.options[0].Selected
	runSAST := m.options[1].Selected
	runSecrets := m.options[2].Selected

	path, cleanup, err := repo.Load(m.target)
	if err != nil {
		return ErrorMsg(err)
	}

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

	if runSBOM {
		m.statuses.Store("SBOM & CVE", "Generating CycloneDX SBOM...")
		eg.Go(func() error {
			components, _ = sbom.Generate(path)
			m.statuses.Store("SBOM & CVE", "Querying VulnerableCode & OSV...")
			findings, _ = cve.QueryVulnerableCode(components)
			if len(findings) == 0 {
				findings, _ = cve.QueryOSV(components)
			}
			m.statuses.Store("SBOM & CVE", "Done.")
			return nil
		})
	}

	if runSAST {
		m.statuses.Store("SAST", "Running Semgrep rules...")
		eg.Go(func() error {
			sastFindings, _ = scan.RunSemgrep(path)
			m.statuses.Store("SAST", "Done.")
			return nil
		})
	}

	if runSecrets {
		m.statuses.Store("Secrets", "Running Gitleaks...")
		eg.Go(func() error {
			secretFindings, _ = secrets.RunGitleaks(path)
			m.statuses.Store("Secrets", "Done.")
			return nil
		})
	}

	m.statuses.Store("Attack Surface", "Detecting Entrypoints...")
	eg.Go(func() error {
		surface, _ = attacksurface.Detect(path)
		m.statuses.Store("Attack Surface", "Done.")
		return nil
	})

	if runSBOM {
		m.statuses.Store("Reachability", "Checking CPG Cache...")
		eg.Go(func() error {
			cpgPath, _ = reachability.GenerateCPG(path, report.Repo.Language)
			m.statuses.Store("Reachability", "Done.")
			return nil
		})
	}

	m.statuses.Store("Supply Chain", "Querying OpenSSF API...")
	eg.Go(func() error {
		sc = supplychain.FetchScorecard(path)
		m.statuses.Store("Supply Chain", "Done.")
		return nil
	})

	m.statuses.Store("Threat Model", "Running STRIDE heuristics...")
	eg.Go(func() error {
		tm = threatmodel.Generate(path)
		m.statuses.Store("Threat Model", "Done.")
		return nil
	})

	if err := eg.Wait(); err != nil {
		if cleanup != nil {
			cleanup()
		}
		return ErrorMsg(err)
	}

	report.SBOM.Components = components
	report.Findings = findings
	report.SAST = sastFindings
	report.Secrets = secretFindings
	report.AttackSurface = surface
	report.SupplyChain = sc
	report.ThreatModel = tm

	// Run Reachability Analysis on findings if CPG was generated
	if cpgPath != "" && len(report.Findings) > 0 {
		m.statuses.Store("Reachability", "Analyzing call paths...")
		reachability.Analyze(report, cpgPath)
		m.statuses.Store("Reachability", "Done.")
	}

	// Run Agent Synthesizer
	if m.narrate {
		m.statuses.Store("Agent (AI)", "Synthesizing report narrative...")
		report.AINarrative = agent.Synthesize(report)
		m.statuses.Store("Agent (AI)", "Done.")
	} else {
		m.statuses.Store("Agent (AI)", "Skipped (run with --narrate)")
	}

	return RepoLoadedMsg{
		Report:  report,
		Cleanup: cleanup,
	}
}

func (m AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "1":
			if m.state == StateSelection && len(m.options) > 0 {
				m.options[0].Selected = !m.options[0].Selected
			}
		case "2":
			if m.state == StateSelection && len(m.options) > 1 {
				m.options[1].Selected = !m.options[1].Selected
			}
		case "3":
			if m.state == StateSelection && len(m.options) > 2 {
				m.options[2].Selected = !m.options[2].Selected
			}
		case "enter":
			if m.state == StateSelection {
				m.state = StateScanning
				return m, tea.Batch(m.spinner.Tick, m.loadRepoCmd)
			}
		}
	case RepoLoadedMsg:
		m.report = msg.Report
		if msg.Cleanup != nil {
			msg.Cleanup()
		}
		m.dashboard = newDashboard(m.report)
		m.state = StateDone
		return m, nil
	case ErrorMsg:
		m.err = msg
		m.state = StateDone
		m.quitting = true
		return m, tea.Quit
	case spinner.TickMsg:
		if m.state == StateScanning {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
	}

	if m.state == StateDone {
		var cmd tea.Cmd
		m.dashboard, cmd = m.dashboard.Update(msg)
		return m, cmd
	}

	return m, nil
}

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Margin(1, 0, 1, 2)
	activeStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575")).Bold(true)
	inactiveStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")).Bold(true)
	dimStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("#737373"))
	labelStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0"))
	statKeyStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#A0A0A0")).MarginLeft(2)
	statValStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575")).Bold(true)
	errorStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")).Bold(true).MarginLeft(2)
)

func (m AppModel) View() string {
	if m.err != nil {
		return errorStyle.Render(fmt.Sprintf("Error: %v", m.err)) + "\n\n"
	}

	if m.state == StateDone && m.report != nil {
		return m.dashboard.View()
	}

	if m.state == StateSelection {
		var sb strings.Builder
		sb.WriteString(titleStyle.Render("Select Scanners to Run (Press 1, 2, 3 to toggle, Enter to start):") + "\n\n")
		for i, opt := range m.options {
			mark := inactiveStyle.Render("✗")
			nameStyle := dimStyle
			if opt.Selected {
				mark = activeStyle.Render("✓")
				nameStyle = labelStyle
			}
			sb.WriteString(fmt.Sprintf("  %d. [%s] %s\n", i+1, mark, nameStyle.Render(opt.Name)))
		}
		sb.WriteString("\n" + dimStyle.MarginLeft(2).Render("Press q to quit.") + "\n")
		
		boxStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("205")).
			Padding(1, 2).
			Margin(1, 2)
			
		return "\n" + boxStyle.Render(sb.String()) + "\n"
	}

	if m.state == StateScanning {
		targetDisplay := m.target
		if targetDisplay == "" || targetDisplay == "." {
			targetDisplay = "local directory"
		}
		
		var sb strings.Builder
		scanMsg := lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).Render(fmt.Sprintf("Scanning repository: %s", targetDisplay))
		sb.WriteString(fmt.Sprintf("\n\n   %s %s\n\n", m.spinner.View(), scanMsg))

		sb.WriteString(dimStyle.MarginLeft(6).Render("Live Progress:") + "\n")

		// Predefined keys to maintain order
		keys := []string{
			"SBOM & CVE",
			"SAST",
			"Secrets",
			"Attack Surface",
			"Reachability",
			"Supply Chain",
			"Threat Model",
			"Agent (AI)",
		}

		for _, k := range keys {
			if val, ok := m.statuses.Load(k); ok {
				status := val.(string)
				color := "205" // pink (running)
				if status == "Done." {
					color = "10" // green (done)
				}
				stStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Render(status)
				sb.WriteString(fmt.Sprintf("      %-20s %s\n", k, stStyle))
			}
		}
		sb.WriteString("\n")
		return sb.String()
	}

	if m.quitting {
		return dimStyle.MarginLeft(2).Render("Exiting...") + "\n"
	}

	return ""
}
