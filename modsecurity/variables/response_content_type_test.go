package variables

import (
	"testing"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
	"github.com/hsluoyz/modsecurity-go/utils"
)

func TestVariableResponseContentType(t *testing.T) {
	v := NewVariableResponseContentType()
	if v.Name() != "RESPONSE_CONTENT_TYPE" {
		t.Errorf("got unexcepted variable name %s", v.Name())
		return
	}
	engine := modsecurity.NewEngine()
	t.Run("no content type", func(t *testing.T) {
		tr, err := modsecurity.NewTransaction(engine, modsecurity.NewSecRuleSet())
		if err != nil {
			t.Error(err)
			return
		}
		header := map[string][]string{}
		tr.ProcessResponseHeaders(200, "HTTP/1.1", header)
		res := v.Fetch(tr)

		if !utils.SameStringSlice(res, []string{"application/octet-stream"}) {
			t.Errorf("variable args get fail got %q", res)
		}
	})
	t.Run("contentType", func(t *testing.T) {
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

		if !utils.SameStringSlice(res, []string{"application/x-www-form-urlencoded"}) {
			t.Errorf("variable args get fail got %q", res)
		}
	})
}
