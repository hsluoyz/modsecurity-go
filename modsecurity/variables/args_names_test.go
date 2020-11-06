package variables

import (
	"net/url"
	"testing"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
	"github.com/hsluoyz/modsecurity-go/utils"
)

func TestVariableArgsNames(t *testing.T) {
	v := NewVariableArgsNames()
	if v.Name() != "ARGS_NAMES" {
		t.Errorf("got unexcepted variable name %s", v.Name())
		return
	}
	v.Include(`/a/`)
	u, _ := url.Parse("http://localhost/query?a1=1&a2=2&b1=3&b2=4")
	header := map[string][]string{
		"Content-Type": {"application/x-www-form-urlencoded"},
	}
	body := `a3=5&a4=6&b3=7&b4=8`
	eng := modsecurity.NewEngine()
	eng.RequestBodyAccess = true
	tr, err := modsecurity.NewTransaction(eng, modsecurity.NewSecRuleSet())
	if err != nil {
		t.Error(err)
	}
	tr.ProcessRequestURL(u, "POST", "HTTP/1.1")
	tr.ProcessRequestHeader(header)
	tr.AppendRequestBody([]byte(body))
	res := v.Fetch(tr)
	if !utils.SameStringSlice(res, []string{"a1", "a2", "a3", "a4"}) {
		t.Errorf("variable args get fail got %q", res)
	}
}
