package variables

import (
	"strconv"

	"github.com/senghoo/modsecurity-go/modsecurity"
)

func NewVariableResponseStatus() modsecurity.Variable {
	return &VariableResponseStatus{}
}

type VariableResponseStatus struct {
}

func (*VariableResponseStatus) Name() string {
	return "RESPONSE_STATUS"
}
func (*VariableResponseStatus) Include(string) error { return nil }
func (*VariableResponseStatus) Exclude(string) error { return nil }
func (*VariableResponseStatus) Fetch(t *modsecurity.Transaction) []string {
	return []string{strconv.Itoa(t.Response.Code)}
}
