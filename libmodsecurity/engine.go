package libmodsecruity

type Engine struct {
	enabled            bool
	detectionOnly      bool
	requestBodyAccess  bool
	responseBodyAccess bool
}

func NewEngine() *Engine {
	return &Engine{}
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
		e.enabled = true
		e.detectionOnly = false
	case StatusOff:
		e.enabled = false
		e.detectionOnly = false
	case StatusDect:
		e.enabled = false
		e.detectionOnly = true
	}
}

func (e *Engine) AddRuleSet(rs *RuleSet) error {
	return rs.Execute(e)
}

func (e *Engine) RequestBodyAccess(b bool) {
	e.requestBodyAccess = b
}
func (e *Engine) ResponseBodyAccess(b bool) {
	e.responseBodyAccess = b
}
