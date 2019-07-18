package actions

import (
	"testing"

	"github.com/senghoo/modsecurity-go/modsecurity"
)

func TestStatus(t *testing.T) {
	engine := modsecurity.NewEngine()
	ruleSet := modsecurity.NewSecRuleSet()
	tr, err := modsecurity.NewTransaction(engine, ruleSet)
	if err != nil {
		t.Error(err)
		return
	}
	status := NewActionStatus(444)
	status.Do(tr)
	deny := NewActionDeny()
	deny.Do(tr)
	i := tr.Intervention()
	if i.Status != 444 {
		t.Errorf("unexpected status %d", i.Status)
	}
	if !i.Disruptive {
		t.Error("not disruptive")
	}
}
