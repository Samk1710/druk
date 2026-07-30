package agent

import "fmt"

// Budget enforces limits on agent sessions to prevent infinite loops and manage costs.
type Budget struct {
	MaxTurns int
	Turn     int
}

// NewBudget initializes a new session budget. Defaulting to 15 turns for Q&A loops.
func NewBudget(maxTurns int) *Budget {
	if maxTurns <= 0 {
		maxTurns = 15
	}
	return &Budget{
		MaxTurns: maxTurns,
		Turn:     0,
	}
}

// Increment adds to the turn counter and returns an error if the budget is exceeded.
func (b *Budget) Increment() error {
	b.Turn++
	if b.Turn > b.MaxTurns {
		return fmt.Errorf("agent session budget exceeded: reached maximum of %d tool-calling turns. Halting to prevent runaway costs", b.MaxTurns)
	}
	return nil
}
