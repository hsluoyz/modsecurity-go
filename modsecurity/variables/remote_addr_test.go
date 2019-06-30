package variables

import (
	"testing"

	"github.com/senghoo/modsecurity-go/modsecurity"
)

func TestVariableRemoteAddr(t *testing.T) {
	v := NewVariableRemoteAddr()
	if v.Name() != "REMOTE_ADDR" {
		t.Errorf("got unexcepted variable name %s", v.Name())
		return
	}
	tr, err := modsecurity.NewTransaction(modsecurity.NewEngine(), modsecurity.NewSecRuleSet())
	if err != nil {
		t.Error(err)
		return
	}
	srcIP := "192.168.1.1"
	tr.ProcessConnection(srcIP, "12345", "1.1.1.1", "80")
	vars := v.Fetch(tr)

	if len(vars) != 1 {
		t.Errorf("unexcepted count %d", len(vars))
		return
	}
	if vars[0] != srcIP {
		t.Errorf("variable args get fail got %q", vars)
		return
	}
}
