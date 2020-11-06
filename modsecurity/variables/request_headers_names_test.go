package variables

import (
	"net/url"
	"testing"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
	"github.com/hsluoyz/modsecurity-go/utils"
)

func TestVariableRequestHeadersNames(t *testing.T) {
	v := NewVariableRequestHeadersNames()
	if v.Name() != "REQUEST_HEADERS_NAMES" {
		t.Errorf("got unexcepted variable name %s", v.Name())
		return
	}
	engine := modsecurity.NewEngine()
	t.Run("headersNames", func(t *testing.T) {
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

		if !utils.SameStringSlice(res, []string{"Content-Type", "Content-Length"}) {
			t.Errorf("variable args get fail got %q", res)
		}
	})
}
