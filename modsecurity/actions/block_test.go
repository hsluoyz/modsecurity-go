package actions

import (
	"testing"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
)

func TestBlock(t *testing.T) {
	engine := modsecurity.NewEngine()
	ruleSet := modsecurity.NewSecRuleSet()
	ruleSet.AddDefaultActions(NewActionDeny(), NewActionLog())
	tr, err := modsecurity.NewTransaction(engine, ruleSet)
	if err != nil {
		t.Error(err)
		return
	}
	block := NewActionBlock()
	block.Do(tr)
	i := tr.Intervention()
	if i.Status != 403 {
		t.Errorf("unexpected status %d", i.Status)
	}
	if !i.Disruptive {
		t.Error("not disruptive")
	}
	if len(i.Log) != 2 {
		t.Errorf("expect two log but got %d", len(i.Log))
	}
}
