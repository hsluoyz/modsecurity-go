package variables

import (
	"github.com/hsluoyz/modsecurity-go/modsecurity"
)

func NewVariableRequestCookiesNames() modsecurity.Variable {
	return &VariableRequestCookiesNames{
		filter: &filter{},
	}
}

type VariableRequestCookiesNames struct {
	*filter
}

func (*VariableRequestCookiesNames) Name() string {
	return "REQUEST_COOKIES_NAMES"
}
func (v *VariableRequestCookiesNames) Fetch(t *modsecurity.Transaction) []string {
	if t == nil || t.Request.Header == nil {
		return nil
	}
	return v.filter.Names(readCookie(t.Request.Header))
}
