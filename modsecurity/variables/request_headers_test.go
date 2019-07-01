package variables

import (
	"net/url"
	"testing"

	"github.com/senghoo/modsecurity-go/modsecurity"
	"github.com/senghoo/modsecurity-go/utils"
)

func TestVariableRequestHeaders(t *testing.T) {
	v := NewVariableRequestHeaders()
	if v.Name() != "REQUEST_HEADERS" {
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
		u, _ := url.Parse("http://localhost/query")
		header := map[string][]string{
			"Content-Type":   {"application/x-www-form-urlencoded"},
			"Content-Length": {"0"},
		}
		tr.ProcessRequestURL(u, "POST", "HTTP/1.1")
		tr.ProcessRequestHeader(header)
		res := v.Fetch(tr)

		if !utils.SameStringSlice(res, []string{"application/x-www-form-urlencoded", "0"}) {
			t.Errorf("variable args get fail got %q", res)
		}
	})
}
