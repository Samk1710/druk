package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/samk/druk/internal/agent"
	"github.com/samk/druk/internal/model"
)

var (
	tabStyle         = lipgloss.NewStyle().Border(lipgloss.NormalBorder(), true).BorderForeground(lipgloss.Color("240")).Padding(0, 1)
	activeTabStyle   = tabStyle.BorderForeground(lipgloss.Color("205")).Foreground(lipgloss.Color("205")).Bold(true)
	tabWindowStyle   = lipgloss.NewStyle().Border(lipgloss.NormalBorder(), true).BorderForeground(lipgloss.Color("240")).Padding(1, 2)
)

type dashboardModel struct {
	activeTab    int
	vulnTable    table.Model
	sastTable    table.Model
	secretsTable table.Model
	report       *model.Report
	chatInput    textinput.Model
	chatHistory  []string
	chatLoading  bool
}

func newDashboard(report *model.Report) dashboardModel {
	vulnColumns := []table.Column{
		{Title: "ID", Width: 15},
		{Title: "Package", Width: 20},
		{Title: "Version", Width: 10},
		{Title: "Severity", Width: 10},
		{Title: "Reachability", Width: 15},
	}
	var vulnRows []table.Row
	for _, f := range report.Findings {
		vulnRows = append(vulnRows, table.Row{f.ID, f.Package, f.Version, f.Severity, f.Reachability})
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
	tSast := table.New(
		table.WithColumns(sastColumns),
		table.WithRows(sastRows),
		table.WithFocused(true),
		table.WithHeight(10),
	)
	tSast.SetStyles(s)

	secretsColumns := []table.Column{
		{Title: "Scanner", Width: 10},
		{Title: "Severity", Width: 10},
		{Title: "File", Width: 30},
		{Title: "Message", Width: 40},
	}
	var secretsRows []table.Row
	for _, sec := range report.Secrets {
		secretsRows = append(secretsRows, table.Row{"Gitleaks", sec.Severity, fmt.Sprintf("%s:%d", sec.Path, sec.Line), sec.RuleID})
	}
	tSecrets := table.New(
		table.WithColumns(secretsColumns),
		table.WithRows(secretsRows),
		table.WithFocused(true),
		table.WithHeight(10),
	)
	tSecrets.SetStyles(s)

	ti := textinput.New()
	ti.Placeholder = "Ask a question about the security report..."
	ti.Focus()
	ti.CharLimit = 256
	ti.Width = 80

	return dashboardModel{
		activeTab:    0,
		vulnTable:    tVuln,
		sastTable:    tSast,
		secretsTable: tSecrets,
		report:       report,
		chatInput:    ti,
		chatHistory:  []string{"Agent: I am a grounded Q&A agent. I can search findings, get call paths, and view supply chain scores. How can I help?"},
	}
}

type agentRequestMsg struct {
	prompt string
}

type agentResponseMsg struct {
	messages []agent.Message
	err      error
}

func (m dashboardModel) Update(msg tea.Msg) (dashboardModel, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case agentResponseMsg:
		m.chatLoading = false
		if msg.err != nil {
			m.chatHistory = append(m.chatHistory, "Error: "+msg.err.Error())
		} else {
			// Update history
			m.chatHistory = []string{"Agent: I am a grounded Q&A agent. I can search findings, get call paths, and view supply chain scores. How can I help?"}
			for _, amsg := range msg.messages {
				if amsg.Role == "user" {
					m.chatHistory = append(m.chatHistory, "You: "+amsg.Content)
				} else if amsg.Role == "assistant" && amsg.Content != "" {
					m.chatHistory = append(m.chatHistory, "Agent: "+amsg.Content)
				}
			}
		}
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "tab":
			m.activeTab = (m.activeTab + 1) % 7
			return m, nil
		case "shift+tab":
			m.activeTab = (m.activeTab - 1 + 7) % 7
			return m, nil
		case "enter":
			if m.activeTab == 6 && !m.chatLoading && m.chatInput.Value() != "" {
				val := m.chatInput.Value()
				m.chatInput.SetValue("")
				m.chatHistory = append(m.chatHistory, "You: "+val)
				m.chatLoading = true

				// Reconstruct conversation for the agent
				var msgs []agent.Message
				for _, h := range m.chatHistory {
					if strings.HasPrefix(h, "You: ") {
						msgs = append(msgs, agent.Message{Role: "user", Content: strings.TrimPrefix(h, "You: ")})
					} else if strings.HasPrefix(h, "Agent: ") && h != "Agent: I am a grounded Q&A agent. I can search findings, get call paths, and view supply chain scores. How can I help?" {
						msgs = append(msgs, agent.Message{Role: "assistant", Content: strings.TrimPrefix(h, "Agent: ")})
					}
				}
				
				report := m.report // capture for closure
				cmd = func() tea.Msg {
					client, err := agent.NewClient()
					if err != nil {
						return agentResponseMsg{err: err}
					}
					// Add system prompt to guide it to use tools
					systemMsg := agent.Message{
						Role: "system",
						Content: "You are a helpful security agent. You must use the provided tools to answer questions about the security report. Do not guess or hallucinate answers.",
					}
					fullMsgs := append([]agent.Message{systemMsg}, msgs...)
					
					finalMsgs, err := agent.ChatLoop(client, report, fullMsgs)
					// strip system prompt
					if len(finalMsgs) > 0 {
						finalMsgs = finalMsgs[1:]
					}
					return agentResponseMsg{messages: finalMsgs, err: err}
				}
				return m, cmd
			}
		case "1", "2", "3", "4", "5", "6", "7":
			// Don't intercept number keys if we are typing in the chat tab
			if m.activeTab != 6 {
				switch msg.String() {
				case "1": m.activeTab = 0
				case "2": m.activeTab = 1
				case "3": m.activeTab = 2
				case "4": m.activeTab = 3
				case "5": m.activeTab = 4
				case "6": m.activeTab = 5
				case "7": m.activeTab = 6
				}
				return m, nil
			}
		}
	}

	if m.activeTab == 1 {
		m.vulnTable, cmd = m.vulnTable.Update(msg)
	} else if m.activeTab == 2 {
		m.sastTable, cmd = m.sastTable.Update(msg)
	} else if m.activeTab == 3 {
		m.secretsTable, cmd = m.secretsTable.Update(msg)
	} else if m.activeTab == 6 {
		m.chatInput, cmd = m.chatInput.Update(msg)
	}
	return m, cmd
}

func (m dashboardModel) View() string {
	tabs := []string{
		"Overview",
		"Vulnerabilities",
		"SAST",
		"Secrets",
		"Supply Chain",
		"Threat Model",
		"Chat",
	}
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
		
		// Metrics column
		metrics := fmt.Sprintf("Detected Language: %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#FF00FF")).Bold(true).Render(m.report.Repo.Language))
		metrics += fmt.Sprintf("Entrypoints:       %d\n\n", len(m.report.AttackSurface.Entrypoints))
		metrics += fmt.Sprintf("Dependencies:      %d\n", len(m.report.SBOM.Components))
		metrics += fmt.Sprintf("Vulnerabilities:   %d\n", len(m.report.Findings))
		metrics += fmt.Sprintf("SAST Issues:       %d\n", len(m.report.SAST))
		metrics += fmt.Sprintf("Secrets Found:     %d\n", len(m.report.Secrets))

		if m.report.AINarrative.Summary != "" {
			var ai strings.Builder
			ai.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true).Render(fmt.Sprintf("✦ AI Executive Summary (%s) ✦\n\n", m.report.AINarrative.ModelUsed)))
			// Word wrap the summary roughly
			ai.WriteString(m.report.AINarrative.Summary + "\n\n")
			
			ai.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true).Render("Prioritized Actions:\n"))
			for i, action := range m.report.AINarrative.PrioritizedActions {
				ai.WriteString(fmt.Sprintf("%d. %s\n", i+1, action))
			}

			// Render side by side
			metricsBox := lipgloss.NewStyle().PaddingRight(4).Render(metrics)
			aiBox := lipgloss.NewStyle().Width(80).Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("63")).Padding(1, 2).Render(ai.String())
			sb.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, metricsBox, aiBox))
		} else {
			sb.WriteString(metrics)
		}

		content = sb.String()
	case 1:
		content = m.vulnTable.View()
	case 2:
		content = m.sastTable.View()
	case 3:
		content = m.secretsTable.View()
	case 4:
		// Supply Chain View
		var sc strings.Builder
		sc.WriteString(titleStyle.Render("Supply Chain Security Score") + "\n\n")
		if m.report.SupplyChain.IsScorecard {
			scoreColor := lipgloss.Color("10") // green
			if m.report.SupplyChain.Score < 7 {
				scoreColor = lipgloss.Color("9") // red
			}
			scStyle := lipgloss.NewStyle().Foreground(scoreColor).Bold(true).Render(fmt.Sprintf("%.1f / 10", m.report.SupplyChain.Score))
			sc.WriteString("OpenSSF Scorecard: " + scStyle + "\n\n")
			for _, check := range m.report.SupplyChain.Checks {
				color := "10"
				if check.Score < 10 {
					color = "11"
				}
				if check.Score <= 0 {
					color = "9"
				}
				pts := lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Render(fmt.Sprintf("[%2d/10]", check.Score))
				sc.WriteString(fmt.Sprintf("%s %s\n", pts, check.Name))
				if check.Score < 10 {
					sc.WriteString(dimStyle.Render("      └─ "+check.Reason) + "\n")
				}
			}
		} else {
			sc.WriteString("OpenSSF Scorecard data unavailable.\n")
			sc.WriteString(dimStyle.Render("(Repository is local, private, or not currently tracked by OpenSSF)"))
		}
		content = sc.String()
	case 5:
		// Threat Model View
		var tm strings.Builder
		tm.WriteString(titleStyle.Render("STRIDE Threat Model") + "\n\n")
		
		tm.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true).Render("Detected Assets:"))
		tm.WriteString("\n")
		if len(m.report.ThreatModel.Assets) == 0 {
			tm.WriteString("  None automatically detected\n")
		} else {
			for _, a := range m.report.ThreatModel.Assets {
				tm.WriteString(fmt.Sprintf("  • %s\n", a))
			}
		}
		tm.WriteString("\n")

		tm.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true).Render("Detected Trust Boundaries:"))
		tm.WriteString("\n")
		if len(m.report.ThreatModel.TrustBoundaries) == 0 {
			tm.WriteString("  None automatically detected\n")
		} else {
			for _, t := range m.report.ThreatModel.TrustBoundaries {
				tm.WriteString(fmt.Sprintf("  • %s\n", t))
			}
		}
		tm.WriteString("\n")

		tm.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true).Render("Identified Risks (STRIDE):"))
		tm.WriteString("\n")
		for _, risk := range m.report.ThreatModel.STRIDE {
			tm.WriteString(fmt.Sprintf("  [%s] %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Render(risk.Category), risk.Description))
			tm.WriteString(fmt.Sprintf("      ↳ %s\n", dimStyle.Render("Mitigation: "+risk.Mitigation)))
			tm.WriteString("\n")
		}
		if len(m.report.ThreatModel.STRIDE) == 0 {
			tm.WriteString("  No heuristic risks mapped.\n")
		}

		content = tm.String()
	case 6:
		// Chat View
		var chat strings.Builder
		for _, msg := range m.chatHistory {
			chat.WriteString(msg + "\n\n")
		}
		if m.chatLoading {
			chat.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Render("Agent is thinking... (running tools)") + "\n\n")
		}
		chat.WriteString(m.chatInput.View())
		content = chat.String()
	}

	return lipgloss.JoinVertical(lipgloss.Left, row, tabWindowStyle.Render(content))
}
