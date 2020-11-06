package variables

import (
	"testing"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
	"github.com/hsluoyz/modsecurity-go/utils"
)

func TestVariableResponseHeaders(t *testing.T) {
	v := NewVariableResponseHeaders()
	if v.Name() != "RESPONSE_HEADERS" {
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

		if !utils.SameStringSlice(res, []string{"application/x-www-form-urlencoded", "0"}) {
			t.Errorf("variable args get fail got %q", res)
		}
	})
}
