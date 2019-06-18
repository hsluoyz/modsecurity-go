package modsecurity

type Engine struct {
	Enabled            bool
	DetectionOnly      bool
	RequestBodyAccess  bool
	ResponseBodyAccess bool
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
