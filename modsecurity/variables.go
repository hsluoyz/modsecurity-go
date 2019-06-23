package modsecurity

import (
	"net/url"
	"strconv"
)

type Variable interface {
	Name() string
	Include(string) error
	Exclude(string) error
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
func (*VariableRequestURI) Include(string) error { return nil }
func (*VariableRequestURI) Exclude(string) error { return nil }
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

func NewCountVariable(v Variable) Variable {
	return &CountVariable{v}
}

type CountVariable struct {
	Variable
}

func (v *CountVariable) Fetch(t *Transaction) []string {
	return []string{strconv.Itoa(len(v.Variable.Fetch(t)))}
}
