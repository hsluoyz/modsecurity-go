package variables

import (
	"net/url"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
)

func NewVariableRequestURI() modsecurity.Variable {
	return &VariableRequestURI{}
}

type VariableRequestURI struct {
}

func (*VariableRequestURI) Name() string {
	return "REQUEST_URI"
}
func (*VariableRequestURI) Include(string) error { return nil }
func (*VariableRequestURI) Exclude(string) error { return nil }
func (*VariableRequestURI) Fetch(t *modsecurity.Transaction) []string {
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
