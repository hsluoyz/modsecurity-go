package modsecurity

import (
	"net/url"
)

type Variable interface {
	Name() string
	Include(string)
	Exclude(string)
	Fetch(*Transaction) []string
}

func NewVariableRequestURI() Variable {
	return &VariableRequestURI{}
}

type VariableRequestURI struct {
}

func (*VariableRequestURI) Name() string {
	return "REQUEST_URI"
}
func (*VariableRequestURI) Include(string) {}
func (*VariableRequestURI) Exclude(string) {}
func (*VariableRequestURI) Fetch(t *Transaction) []string {
	if t.URL == nil {
		return nil
	}
	u := new(url.URL)
	*u = *t.URL
	u.Scheme = ""
	u.Host = ""
	u.Opaque = ""
	u.User = nil
	return []string{u.String()}
}
