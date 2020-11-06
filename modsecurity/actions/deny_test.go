package actions

import (
	"testing"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
)

func TestDeny(t *testing.T) {
	engine := modsecurity.NewEngine()
	ruleSet := modsecurity.NewSecRuleSet()
	tr, err := modsecurity.NewTransaction(engine, ruleSet)
	if err != nil {
		t.Error(err)
		return
	}
	deny := NewActionDeny()
	deny.Do(tr)
	i := tr.Intervention()
	if i.Status != 403 {
		t.Errorf("unexpected status %d", i.Status)
	}
	if !i.Disruptive {
		t.Error("not disruptive")
	}
}
