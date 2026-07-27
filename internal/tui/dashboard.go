package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/samk/druk/internal/model"
)

var (
	tabStyle         = lipgloss.NewStyle().Border(lipgloss.NormalBorder(), true).BorderForeground(lipgloss.Color("240")).Padding(0, 1)
	activeTabStyle   = tabStyle.BorderForeground(lipgloss.Color("205")).Foreground(lipgloss.Color("205")).Bold(true)
	tabWindowStyle   = lipgloss.NewStyle().Border(lipgloss.NormalBorder(), true).BorderForeground(lipgloss.Color("240")).Padding(1, 2)
)

type dashboardModel struct {
	activeTab int
	vulnTable table.Model
	sastTable table.Model
	report    *model.Report
}

func newDashboard(report *model.Report) dashboardModel {
	vulnColumns := []table.Column{
		{Title: "ID", Width: 15},
		{Title: "Package", Width: 20},
		{Title: "Version", Width: 10},
		{Title: "Severity", Width: 10},
	}
	var vulnRows []table.Row
	for _, f := range report.Findings {
		vulnRows = append(vulnRows, table.Row{f.ID, f.Package, f.Version, f.Severity})
	}
	tVuln := table.New(
		table.WithColumns(vulnColumns),
		table.WithRows(vulnRows),
		table.WithFocused(true),
		table.WithHeight(10),
	)
	s := table.DefaultStyles()
	s.Header = s.Header.BorderStyle(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("240")).BorderBottom(true).Bold(true)
	s.Selected = s.Selected.Foreground(lipgloss.Color("229")).Background(lipgloss.Color("57")).Bold(false)
	tVuln.SetStyles(s)

	sastColumns := []table.Column{
		{Title: "Scanner", Width: 10},
		{Title: "Severity", Width: 10},
		{Title: "File", Width: 30},
		{Title: "Message", Width: 40},
	}
	var sastRows []table.Row
	for _, s := range report.SAST {
		sastRows = append(sastRows, table.Row{"Semgrep", s.Severity, fmt.Sprintf("%s:%d", s.Path, s.Line), s.Message})
	}
	for _, sec := range report.Secrets {
		sastRows = append(sastRows, table.Row{"Gitleaks", sec.Severity, fmt.Sprintf("%s:%d", sec.Path, sec.Line), sec.RuleID})
	}
	tSast := table.New(
		table.WithColumns(sastColumns),
		table.WithRows(sastRows),
		table.WithFocused(true),
		table.WithHeight(10),
	)
	tSast.SetStyles(s)

	return dashboardModel{
		activeTab: 0,
		vulnTable: tVuln,
		sastTable: tSast,
		report:    report,
	}
}

func (m dashboardModel) Update(msg tea.Msg) (dashboardModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab":
			m.activeTab = (m.activeTab + 1) % 3
			return m, nil
		case "shift+tab":
			m.activeTab = (m.activeTab - 1 + 3) % 3
			return m, nil
		}
	}

	var cmd tea.Cmd
	if m.activeTab == 1 {
		m.vulnTable, cmd = m.vulnTable.Update(msg)
	} else if m.activeTab == 2 {
		m.sastTable, cmd = m.sastTable.Update(msg)
	}
	return m, cmd
}

func (m dashboardModel) View() string {
	tabs := []string{"Overview", "Vulnerabilities", "SAST & Secrets"}
	var renderedTabs []string
	for i, t := range tabs {
		if i == m.activeTab {
			renderedTabs = append(renderedTabs, activeTabStyle.Render(t))
		} else {
			renderedTabs = append(renderedTabs, tabStyle.Render(t))
		}
	}
	row := lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...)

	var content string
	switch m.activeTab {
	case 0:
		var sb strings.Builder
		sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Render("Analysis Complete\n\n"))
		sb.WriteString(fmt.Sprintf("Detected Language: %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#FF00FF")).Bold(true).Render(m.report.Repo.Language)))
		sb.WriteString(fmt.Sprintf("Entrypoints:       %d\n\n", len(m.report.AttackSurface.Entrypoints)))
		sb.WriteString(fmt.Sprintf("Dependencies:      %d\n", len(m.report.SBOM.Components)))
		sb.WriteString(fmt.Sprintf("Vulnerabilities:   %d\n", len(m.report.Findings)))
		sb.WriteString(fmt.Sprintf("SAST Issues:       %d\n", len(m.report.SAST)))
		sb.WriteString(fmt.Sprintf("Secrets Found:     %d\n", len(m.report.Secrets)))
		content = sb.String()
	case 1:
		content = m.vulnTable.View()
	case 2:
		content = m.sastTable.View()
	}

	return lipgloss.JoinVertical(lipgloss.Left, row, tabWindowStyle.Render(content))
}
