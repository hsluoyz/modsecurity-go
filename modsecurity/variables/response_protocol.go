package variables

import (
	"github.com/hsluoyz/modsecurity-go/modsecurity"
)

func NewVariableResponseProtocol() modsecurity.Variable {
	return &VariableResponseProtocol{}
}

type VariableResponseProtocol struct {
}

func (*VariableResponseProtocol) Name() string {
	return "RESPONSE_PROTOCOL"
}
func (*VariableResponseProtocol) Include(string) error { return nil }
func (*VariableResponseProtocol) Exclude(string) error { return nil }
func (*VariableResponseProtocol) Fetch(t *modsecurity.Transaction) []string {
	return []string{t.Response.Proto}
}
