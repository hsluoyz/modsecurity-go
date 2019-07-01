package variables

import (
	"testing"

	"github.com/senghoo/modsecurity-go/modsecurity"
	"github.com/senghoo/modsecurity-go/utils"
)

func TestVariableResponseContentLength(t *testing.T) {
	v := NewVariableResponseContentLength()
	if v.Name() != "RESPONSE_CONTENT_LENGTH" {
		t.Errorf("got unexcepted variable name %s", v.Name())
		return
	}
	engine := modsecurity.NewEngine()
	t.Run("no content length", func(t *testing.T) {
		tr, err := modsecurity.NewTransaction(engine, modsecurity.NewSecRuleSet())
		if err != nil {
			t.Error(err)
			return
		}
		header := map[string][]string{
			"Content-Type": {"application/x-www-form-urlencoded"},
		}
		tr.ProcessResponseHeaders(200, "HTTP/1.1", header)
		res := v.Fetch(tr)

		if !utils.SameStringSlice(res, []string{"0"}) {
			t.Errorf("variable args get fail got %q", res)
		}
	})
	t.Run("contentLength", func(t *testing.T) {
		tr, err := modsecurity.NewTransaction(engine, modsecurity.NewSecRuleSet())
		if err != nil {
			t.Error(err)
			return
		}
		header := map[string][]string{
			"Content-Type":   {"application/x-www-form-urlencoded"},
			"Content-Length": {"123"},
		}
		tr.ProcessResponseHeaders(200, "HTTP/1.1", header)
		res := v.Fetch(tr)

		if !utils.SameStringSlice(res, []string{"123"}) {
			t.Errorf("variable args get fail got %q", res)
		}
	})
}
