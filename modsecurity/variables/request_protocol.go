package variables

import (
	"github.com/hsluoyz/modsecurity-go/modsecurity"
)

func NewVariableRequestProtocol() modsecurity.Variable {
	return &VariableRequestProtocol{}
}

type VariableRequestProtocol struct {
}

func (*VariableRequestProtocol) Name() string {
	return "REQUEST_PROTOCOL"
}
func (*VariableRequestProtocol) Include(string) error { return nil }
func (*VariableRequestProtocol) Exclude(string) error { return nil }
func (*VariableRequestProtocol) Fetch(t *modsecurity.Transaction) []string {
	return []string{t.Request.Proto}
}
