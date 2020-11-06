package variables

import (
	"github.com/hsluoyz/modsecurity-go/modsecurity"
)

func NewVariableRequestMethod() modsecurity.Variable {
	return &VariableRequestMethod{}
}

type VariableRequestMethod struct {
}

func (*VariableRequestMethod) Name() string {
	return "REQUEST_METHOD"
}
func (*VariableRequestMethod) Include(string) error { return nil }
func (*VariableRequestMethod) Exclude(string) error { return nil }
func (*VariableRequestMethod) Fetch(t *modsecurity.Transaction) []string {
	return []string{t.Request.Method}
}
