package variables

import (
	"testing"

	"github.com/senghoo/modsecurity-go/modsecurity"
)

func TestVariableResponseBody(t *testing.T) {
	v := NewVariableResponseBody()
	if v.Name() != "RESPONSE_BODY" {
		t.Errorf("got unexcepted variable name %s", v.Name())
		return
	}
	engine := modsecurity.NewEngine()
	engine.ResponseBodyAccess = true
	t.Run("none body", func(t *testing.T) {
		tr, err := modsecurity.NewTransaction(engine, modsecurity.NewSecRuleSet())
		if err != nil {
			t.Error(err)
			return
		}
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
		body := `123456890-`
		tr.AppendResponseBody([]byte(body))
		res := v.Fetch(tr)
		if len(res) != 1 {
			t.Errorf("variable args get fail got %q", res)
		}
		if res[0] != body {
			t.Errorf("variable args get fail got %q", res)
		}
	})
}
