package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type AppModel struct {
	spinner  spinner.Model
	quitting bool
}

func InitialModel() AppModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	return AppModel{spinner: s}
}

func (m AppModel) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		}
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m AppModel) View() string {
	if m.quitting {
		return "Exiting...\n"
	}
	str := fmt.Sprintf("\n\n   %s Scanning repository...\n\n", m.spinner.View())
	return str
}
