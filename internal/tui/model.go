package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/samk/druk/internal/cve"
	"github.com/samk/druk/internal/model"
	"github.com/samk/druk/internal/repo"
	"github.com/samk/druk/internal/sbom"
)

type RepoLoadedMsg struct {
	Report  *model.Report
	Cleanup func()
}

type ErrorMsg error

type AppModel struct {
	target   string
	spinner  spinner.Model
	quitting bool
	err      error
	report   *model.Report
}

func InitialModel(target string) AppModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	return AppModel{target: target, spinner: s}
}

func (m AppModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, m.loadRepoCmd)
}

func (m AppModel) loadRepoCmd() tea.Msg {
	path, cleanup, err := repo.Load(m.target)
	if err != nil {
		return ErrorMsg(err)
	}

	lang := repo.DetectLanguage(path)

	components, err := sbom.Generate(path)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return ErrorMsg(fmt.Errorf("sbom generation failed: %w", err))
	}

	findings, err := cve.QueryVulnerableCode(components)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return ErrorMsg(fmt.Errorf("cve querying failed: %w", err))
	}

	report := &model.Report{
		Repo: model.RepoInfo{
			Language: lang,
		},
		SBOM: model.SBOM{
			Components: components,
		},
		Findings: findings,
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
		}
	case RepoLoadedMsg:
		m.report = msg.Report
		if msg.Cleanup != nil {
			msg.Cleanup()
		}
		m.quitting = true
		return m, tea.Quit
	case ErrorMsg:
		m.err = msg
		m.quitting = true
		return m, tea.Quit
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m AppModel) View() string {
	if m.err != nil {
		return fmt.Sprintf("\n  Error: %v\n\n", m.err)
	}
	if m.report != nil {
		return fmt.Sprintf("\n  Detected Language: %s\n  Dependencies: %d\n  Vulnerabilities Found: %d\n\n", m.report.Repo.Language, len(m.report.SBOM.Components), len(m.report.Findings))
	}
	if m.quitting {
		return "Exiting...\n"
	}

	targetDisplay := m.target
	if targetDisplay == "" || targetDisplay == "." {
		targetDisplay = "local directory"
	}
	return fmt.Sprintf("\n\n   %s Scanning repository: %s\n\n", m.spinner.View(), targetDisplay)
}
