package variables

import (
	"github.com/senghoo/modsecurity-go/modsecurity"
)

func NewVariableRemoteAddr() modsecurity.Variable {
	return &VariableRemoteAddr{}
}

type VariableRemoteAddr struct {
}

func (*VariableRemoteAddr) Name() string {
	return "REMOTE_ADDR"
}
func (*VariableRemoteAddr) Include(string) error { return nil }
func (*VariableRemoteAddr) Exclude(string) error { return nil }
func (*VariableRemoteAddr) Fetch(t *modsecurity.Transaction) []string {
	return []string{t.SrcIp}
}
