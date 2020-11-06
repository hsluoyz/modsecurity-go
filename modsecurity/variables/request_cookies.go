package variables

import (
	"net/http"
	"strings"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
)

func NewVariableRequestCookies() modsecurity.Variable {
	return &VariableRequestCookies{
		filter: &filter{},
	}
}

type VariableRequestCookies struct {
	*filter
}

func (*VariableRequestCookies) Name() string {
	return "REQUEST_COOKIES"
}
func (v *VariableRequestCookies) Fetch(t *modsecurity.Transaction) []string {
	if t == nil || t.Request.Header == nil {
		return nil
	}
	return v.filter.Fetch(readCookie(t.Request.Header))
}

func readCookie(h http.Header) map[string][]string {
	lines, ok := h["Cookie"]
	if !ok {
		return nil
	}

	res := make(map[string][]string)
	for _, line := range lines {
		parts := strings.Split(strings.TrimSpace(line), ";")
		if len(parts) == 1 && parts[0] == "" {
			continue
		}
		// Per-line attributes
		for i := 0; i < len(parts); i++ {
			parts[i] = strings.TrimSpace(parts[i])
			if len(parts[i]) == 0 {
				continue
			}
			name, val := parts[i], ""
			if j := strings.Index(name, "="); j >= 0 {
				name, val = name[:j], name[j+1:]
			}
			res[name] = append(res[name], val)
		}
	}
	return res
}
