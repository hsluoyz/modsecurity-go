package modsecurity

type Engine struct {
	Enabled       bool
	DetectionOnly bool
	RuleSet       *SecRuleSet
	*Limits
}

type Limits struct {
	RequestBodyAccess  bool
	ResponseBodyAccess bool
	RequestBody        int64
	RequestBodyInMem   int64
	ResponseBody       int64
}

func NewDefaultLimits() *Limits {
	return &Limits{
		RequestBodyInMem: 131072,    // 128kb
		RequestBody:      134217728, // 1gb
		ResponseBody:     524228,    // 512kb
	}
}

func NewEngine() *Engine {
	return &Engine{
		RuleSet: NewSecRuleSet(),
		Limits:  NewDefaultLimits(),
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
