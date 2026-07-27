package tui

import (
	"fmt"
	"golang.org/x/sync/errgroup"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/samk/druk/internal/cve"
	"github.com/samk/druk/internal/model"
	"github.com/samk/druk/internal/repo"
	"github.com/samk/druk/internal/sbom"
	"github.com/samk/druk/internal/scan"
	"github.com/samk/druk/internal/secrets"
)

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
	target   string
	state    State
	spinner  spinner.Model
	quitting bool
	err      error
	report   *model.Report

	options []ScannerOption
	cursor  int
}

func InitialModel(target string) AppModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	opts := []ScannerOption{
		{"SBOM & Vulnerabilities", true},
		{"SAST (Semgrep)", true},
		{"Secrets (Gitleaks)", true},
	}

	return AppModel{
		target:  target,
		state:   StateSelection,
		spinner: s,
		options: opts,
	}
}

func (m AppModel) Init() tea.Cmd {
	// Don't start spinner until we hit Scanning state
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

	if runSBOM {
		eg.Go(func() error {
			var err error
			components, err = sbom.Generate(path)
			if err != nil {
				return fmt.Errorf("sbom generation failed: %w", err)
			}

			findings, err = cve.QueryVulnerableCode(components)
			if err != nil {
				// OSV Fallback
				findings, err = cve.QueryOSV(components)
				if err != nil {
					return fmt.Errorf("cve querying failed (both VC and OSV): %w", err)
				}
			}
			return nil
		})
	}

	if runSAST {
		eg.Go(func() error {
			var err error
			sastFindings, err = scan.RunSemgrep(path)
			if err != nil {
				// Ignore missing binary gracefully
			}
			return nil
		})
	}

	if runSecrets {
		eg.Go(func() error {
			var err error
			secretFindings, err = secrets.RunGitleaks(path)
			if err != nil {
				// Ignore missing binary gracefully
			}
			return nil
		})
	}

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
		m.state = StateDone
		m.quitting = true
		return m, tea.Quit
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
	return m, nil
}

func (m AppModel) View() string {
	if m.err != nil {
		return fmt.Sprintf("\n  Error: %v\n\n", m.err)
	}
	
	if m.state == StateDone && m.report != nil {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("\n  Detected Language: %s\n", m.report.Repo.Language))
		if m.options[0].Selected {
			sb.WriteString(fmt.Sprintf("  Dependencies: %d\n  Vulnerabilities Found: %d\n", len(m.report.SBOM.Components), len(m.report.Findings)))
		}
		if m.options[1].Selected {
			sb.WriteString(fmt.Sprintf("  SAST Issues: %d\n", len(m.report.SAST)))
		}
		if m.options[2].Selected {
			sb.WriteString(fmt.Sprintf("  Secrets Found: %d\n", len(m.report.Secrets)))
		}
		sb.WriteString("\n")
		return sb.String()
	}

	if m.state == StateSelection {
		s := "\n  Select Scanners to Run (Press 1, 2, 3 to toggle, Enter to start):\n\n"
		for i, opt := range m.options {
			checked := " "
			if opt.Selected {
				checked = "x"
			}
			s += fmt.Sprintf("  %d. [%s] %s\n", i+1, checked, opt.Name)
		}
		s += "\n  Press q to quit.\n"
		return s
	}

	if m.state == StateScanning {
		targetDisplay := m.target
		if targetDisplay == "" || targetDisplay == "." {
			targetDisplay = "local directory"
		}
		return fmt.Sprintf("\n\n   %s Scanning repository: %s\n\n", m.spinner.View(), targetDisplay)
	}

	if m.quitting {
		return "Exiting...\n"
	}

	return ""
}
