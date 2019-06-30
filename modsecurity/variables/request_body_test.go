package variables

import (
	"net/url"
	"testing"

	"github.com/senghoo/modsecurity-go/modsecurity"
)

func TestVariableRequestBody(t *testing.T) {
	v := NewVariableRequestBody()
	if v.Name() != "REQUEST_BODY" {
		t.Errorf("got unexcepted variable name %s", v.Name())
		return
	}
	engine := modsecurity.NewEngine()
	engine.RequestBodyAccess = true
	t.Run("none body", func(t *testing.T) {
		tr, err := modsecurity.NewTransaction(engine, modsecurity.NewSecRuleSet())
		if err != nil {
			t.Error(err)
			return
		}
		u, _ := url.Parse("http://localhost/query")
		header := map[string][]string{
			"Content-Type": {"application/x-www-form-urlencoded"},
		}
		tr.ProcessRequestURL(u, "POST", "HTTP/1.1")
		tr.ProcessRequestHeader(header)
		res := v.Fetch(tr)
		if len(res) != 0 {
			t.Errorf("variable args get fail got %q", res)
		}
	})
	t.Run("some body", func(t *testing.T) {
		tr, err := modsecurity.NewTransaction(engine, modsecurity.NewSecRuleSet())
		if err != nil {
			t.Error(err)
			return
		}
		u, _ := url.Parse("http://localhost/query")
		header := map[string][]string{
			"Content-Type": {"application/x-www-form-urlencoded"},
		}
		body := `a1=1&a2=2&b1=3&b2=4`
		tr.ProcessRequestURL(u, "POST", "HTTP/1.1")
		tr.ProcessRequestHeader(header)
		tr.AppendRequestBody([]byte(body))
		res := v.Fetch(tr)
		if len(res) != 1 {
			t.Errorf("variable args get fail got %q", res)
		}
		if res[0] != body {
			t.Errorf("variable args get fail got %q", res)
		}
	})
}
