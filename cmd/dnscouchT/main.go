package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/jrwren/dnscouch"
)

var baseStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.NormalBorder()).
	BorderForeground(lipgloss.Color("240"))

type model struct {
	table table.Model
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			if m.table.Focused() {
				m.table.Blur()
			} else {
				m.table.Focus()
			}
		case "q", "ctrl+c":
			return m, tea.Quit
		case "enter":
			return m, tea.Batch(
				tea.Printf("Let's go to %s!", m.table.SelectedRow()[1]),
			)
		}
	}
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m model) View() string {
	return baseStyle.Render(m.table.View()) + "\n"
}

func main() {
	n := flag.Int("c", 1, "count - number of lookups to make per server")
	tf := flag.Bool("t", false, "query NTP servers instead of DNS servers")
	useIPv6 := flag.Bool("6", false, "query IPv6 servers (DNS only)")
	flag.Parse()
	columns := []table.Column{
		{Title: "RTT", Width: 8},
		{Title: "Server", Width: 15},
		{Title: "Description", Width: 25},
	}
	rows := []table.Row{}
	var rh int
	switch *tf {
	case false:
		dnsServers := dnscouch.ServerMap4
		if *useIPv6 {
			dnsServers = dnscouch.ServerMap6
		}
		rs, err := dnscouch.LookupServersN(dnsServers, *n)
		if err != nil {
			log.Print("error:", err)
		}
		for _, r := range rs {
			ft := r.D.Round(10 * time.Microsecond)
			rows = append(rows, table.Row{ft.String(), r.ServerName, r.Desc})
		}
		rh = len(rs)
	case true:
		rs, err := dnscouch.LookupNTPServersN(*n)
		if err != nil {
			log.Print("error:", err)
		}
		for _, r := range rs {
			ft := r.D.Round(10 * time.Microsecond)
			rows = append(rows, table.Row{ft.String(), r.ServerName, r.Desc})
		}
		rh = len(rs)
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(rh),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(s)

	m := model{t}
	if _, err := tea.NewProgram(m).Run(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}
}
