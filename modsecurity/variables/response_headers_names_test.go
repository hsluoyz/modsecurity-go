package variables

import (
	"testing"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
	"github.com/hsluoyz/modsecurity-go/utils"
)

func TestVariableResponseHeadersNames(t *testing.T) {
	v := NewVariableResponseHeadersNames()
	if v.Name() != "RESPONSE_HEADERS_NAMES" {
		t.Errorf("got unexcepted variable name %s", v.Name())
		return
	}
	engine := modsecurity.NewEngine()
	t.Run("headers", func(t *testing.T) {
		tr, err := modsecurity.NewTransaction(engine, modsecurity.NewSecRuleSet())
		if err != nil {
			t.Error(err)
			return
		}
		header := map[string][]string{
			"Content-Type":   {"application/x-www-form-urlencoded"},
			"Content-Length": {"0"},
		}
		tr.ProcessResponseHeaders(200, "HTTP/1.1", header)
		res := v.Fetch(tr)
		if !utils.SameStringSlice(res, []string{"Content-Type", "Content-Length"}) {
			t.Errorf("variable args get fail got %q", res)
		}
	})
}
