package variables

import (
	"testing"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
)

func TestVariableRequestProtocol(t *testing.T) {
	v := NewVariableRequestProtocol()
	if v.Name() != "REQUEST_PROTOCOL" {
		t.Errorf("got unexcepted variable name %s", v.Name())
		return
	}
	tr, err := modsecurity.NewTransaction(modsecurity.NewEngine(), modsecurity.NewSecRuleSet())
	if err != nil {
		t.Error(err)
		return
	}
	tr.ProcessRequestURL(nil, "GET", "HTTP/1.1")
	vars := v.Fetch(tr)

	if len(vars) != 1 {
		t.Errorf("unexcepted count %d", len(vars))
		return
	}
	if vars[0] != "HTTP/1.1" {
		t.Errorf("variable args get fail got %q", vars)
		return
	}
}
