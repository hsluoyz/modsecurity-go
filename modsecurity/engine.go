package modsecurity

type Engine struct {
	Enabled            bool
	DetectionOnly      bool
	RequestBodyAccess  bool
	ResponseBodyAccess bool
	RuleSet            *SecRuleSet
}

func NewEngine() *Engine {
	return &Engine{
		RuleSet: NewSecRuleSet(),
	}
}

const (
	StatusOn = iota
	StatusOff
	StatusDect
)

// Enable acts like SecRuleEngine. status argument should be `StatusOn`, `StatusOff` or `StatusDect`.
func (e *Engine) Enable(status int) {
	switch status {
	case StatusOn:
		e.Enabled = true
		e.DetectionOnly = false
	case StatusOff:
		e.Enabled = false
		e.DetectionOnly = false
	case StatusDect:
		e.Enabled = false
		e.DetectionOnly = true
	}
}

func (e *Engine) AddSecRule(rules ...*SecRule) {
	e.RuleSet.AddRules(rules...)
}
func (e *Engine) NewTransaction() *Transaction {
	return NewTransaction(e, e.RuleSet)
}
